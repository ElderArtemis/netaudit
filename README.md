# NetAudit

Plataforma de auditoría de redes con descubrimiento en dos fases (**Masscan → Nmap NSE**), histórico en PostgreSQL, progreso en tiempo real vía WebSockets y exportación de informes en PDF.

> ⚠️ **Uso autorizado únicamente.** Lee el [aviso legal](#aviso-legal) antes de ejecutar nada.

---

## Qué hace

NetAudit inventaría hosts y servicios sobre rangos CIDR y enriquece los resultados con scripts NSE (`vuln`, `auth`, `default`) para detectar vulnerabilidades conocidas, credenciales por defecto y configuraciones inseguras. Los hallazgos se guardan en PostgreSQL para mantener histórico comparable entre escaneos, y se consultan desde un dashboard web.

El pipeline combina dos motores en lugar de usar solo uno:

1. **Masscan** barre el rango completo a alta velocidad (10.000 pps por defecto) y devuelve qué IPs tienen puertos abiertos.
2. **Nmap** se lanza *solo* sobre esas IPs y puertos con `-sV -O --script vuln,auth,default`. El XML de salida se parsea con `defusedxml`.

Así un `/24` se recorre en segundos en vez de en horas, y Nmap solo gasta tiempo donde hay algo que mirar.

## Stack

| Capa | Tecnología |
|---|---|
| API | FastAPI (async) + Jinja2 |
| ORM / migraciones | SQLAlchemy 2.x async + Alembic |
| Persistencia | PostgreSQL 16 |
| Cola y pub/sub | Redis 7 |
| Motor de escaneo | Masscan + Nmap (NSE) |
| Informes | ReportLab |
| Frontend | Vanilla JS + WebSockets |

## Arquitectura

```
              ┌──────────────┐         ┌──────────────┐
   navegador  │   FastAPI    │────────▶│  PostgreSQL  │
  ◀──────────▶│   (API+UI)   │         │   histórico  │
   WebSocket  └──────┬───────┘         └──────▲───────┘
                     │ LPUSH                  │
              ┌──────▼───────┐                │
              │    Redis     │                │
              │ cola+pubsub  │                │
              └──────┬───────┘                │
                     │ BLPOP                  │
              ┌──────▼───────┐                │
              │    Worker    │────────────────┘
              │ masscan→nmap │
              └──────────────┘
```

- **API** (`app/main.py`): dashboard Jinja2 + endpoints REST, un router por dominio.
- **Worker** (`app/workers/scan_worker.py`): consume la cola Redis con `BLPOP` y orquesta el pipeline. Instancia única a propósito, para evitar condiciones de carrera con `BLPOP` competitivo.
- **Redis**: cola de jobs, pub/sub de progreso y caché del último estado por escaneo (TTL 1 h), para que un cliente que reconecta no se quede en blanco.

### Modelo de datos

Tablas `scans`, `hosts`, `ports`, `vulnerabilities` con borrado en cascada. Índices únicos en `(scan_id, ip)` y `(host_id, port, protocol)` para evitar duplicados. Severidades canónicas: `critical`, `high`, `medium`, `low`, `info`.

## Puesta en marcha (local)

Requisitos: Docker y Docker Compose.

```bash
git clone https://github.com/<tu-usuario>/netaudit.git
cd netaudit

cp .env.example .env
# Genera un SECRET_KEY propio y edítalo en .env:
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

docker compose up -d --build
docker compose exec api alembic upgrade head
```

Dashboard en <http://localhost:8000>. Logs del worker con `docker compose logs -f worker`.

### Variables de entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://netaudit:netaudit@postgres:5432/netaudit` | Cadena de conexión async a PostgreSQL |
| `REDIS_URL` | `redis://redis:6379/0` | Redis para cola y pub/sub |
| `APP_ENV` | `production` | Entorno de ejecución |
| `SECRET_KEY` | — | **Genera uno propio.** No uses el del ejemplo |
| `MASSCAN_RATE` | `10000` | Paquetes por segundo de masscan |
| `NMAP_TIMING` | `4` | Plantilla de timing de nmap (`-T`) |
| `ROOT_PATH` | vacío | Prefijo si sirves la app tras un reverse proxy en un subpath |

## Uso

1. Desde `/`, crea un escaneo indicando nombre, rango CIDR (ej. `192.168.1.0/24`, admite varios separados por comas), puertos, tasa de masscan y scripts NSE.
2. El backend valida los CIDR con `ipaddress.ip_network`, persiste el escaneo y encola el `scan_id` en Redis.
3. La vista de detalle abre un WebSocket y muestra el progreso en vivo.
4. Al terminar, el escaneo puede exportarse a PDF: portada con parámetros, resumen ejecutivo por severidad, hallazgos críticos y altos destacados, y detalle por host.

### Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/scans/{scan_id}` | Vista de detalle de un escaneo |
| `POST` | `/api/scans` | Crear y encolar un escaneo |
| `GET` | `/api/scans` | Listar escaneos |
| `GET` | `/api/scans/{scan_id}` | Detalle en JSON |
| `DELETE` | `/api/scans/{scan_id}` | Eliminar un escaneo y sus resultados |
| `GET` | `/api/scans/{scan_id}/export.pdf` | Descargar informe PDF |
| `WS` | `/api/scans/ws/{scan_id}` | Progreso en tiempo real |
| `GET` | `/api/hosts` · `/api/hosts/{id}` | Hosts descubiertos |
| `GET` | `/api/vulnerabilities` · `/api/vulnerabilities/summary` | Vulnerabilidades y conteo por severidad |
| `GET` | `/health` | Healthcheck |

Documentación interactiva en `/docs` (generada por FastAPI).

## Seguridad y despliegue

### ⚠️ La aplicación no incluye autenticación

NetAudit **no trae login, ni control de acceso, ni CORS restringido**. Es una decisión consciente para un despliegue en red de laboratorio, pero implica que **cualquiera que alcance la interfaz puede lanzar escaneos contra la red que quiera**, a hasta 100.000 pps.

No la expongas a Internet. Si necesitas alcanzarla desde fuera, ponla detrás de una VPN o de un reverse proxy que haga la autenticación (mTLS, SSO, o como mínimo auth básica).

### Capabilities

Masscan y nmap necesitan `CAP_NET_RAW` para hacer SYN scan. La imagen aplica `setcap` sobre ambos binarios y corre como usuario no-root (UID 10001).

Ojo con un detalle que da problemas: **las file capabilities no se heredan** a procesos hijos lanzados desde Python vía `subprocess`. Si el worker invoca los binarios de esa forma, `setcap` no basta y el contenedor del worker necesita las capabilities añadidas explícitamente:

```yaml
capabilities:
  drop: ["ALL"]
  add: [NET_RAW, NET_ADMIN, NET_BIND_SERVICE]
```

En bare-metal, sin contenedor:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which masscan)
```

### Despliegue en Kubernetes

Este repositorio **no incluye manifiestos de Kubernetes**: contienen Secrets, direcciones IP y nombres de nodo específicos de una infraestructura concreta, y no tienen valor fuera de ella. Si despliegas NetAudit en un clúster, ten en cuenta:

- El worker necesita ver la red que va a escanear. Dentro de la red de pods solo verá la CNI, no la LAN — hará falta `hostNetwork: true` con `dnsPolicy: ClusterFirstWithHostNet`, y programarlo en un nodo que esté en la red objetivo.
- Estrategia `Recreate` en el worker: con `RollingUpdate` convivirían dos consumidores de la cola.
- API y worker comparten imagen y cambian solo el `command`.
- Las credenciales van en un `Secret` cifrado (SealedSecrets, SOPS, External Secrets…), **nunca en YAML plano dentro del repositorio**.

## Decisiones técnicas

- **Masscan + Nmap en vez de solo Nmap** — masscan descubre, nmap enriquece. Órdenes de magnitud más rápido sobre rangos grandes.
- **`defusedxml` en vez de `xml.etree`** — defensa en profundidad al parsear XML de nmap. Coste casi nulo.
- **WebSockets + pub/sub en vez de polling** — el worker publica progreso y la API lo reenvía, sin martillear la base de datos.
- **Worker de instancia única** — la cola Redis garantiza orden FIFO y se evitan carreras con `BLPOP` competitivo.
- **ReportLab en vez de WeasyPrint** — sin dependencias de Cairo/Pango en la imagen y más control sobre la maquetación.

## Roadmap

- [ ] Cancelación de escaneos en curso (el modelo lo soporta, falta el handler).
- [ ] Comparativa entre escaneos para detectar drift de configuración.
- [ ] Enriquecimiento de CVEs con CVSS desde NVD.
- [ ] Exportación a CSV/XLSX.
- [ ] Scheduler interno para escaneos recurrentes.
- [ ] Autenticación y multi-tenant.

## Aviso legal

NetAudit debe usarse **únicamente sobre redes propias o con autorización expresa y por escrito de su titular**. El escaneo no autorizado de redes ajenas está tipificado en el **artículo 197 bis del Código Penal español** y en normas equivalentes de otras jurisdicciones.

La herramienta no se ofusca, no fragmenta paquetes ni intenta evadir firewalls o sistemas de detección: está diseñada para auditorías legítimas en entornos controlados. El autor no se hace responsable del uso que se le dé.

## Licencia

Pendiente de definir. Sin licencia explícita, se aplican los derechos de autor por defecto: puedes leer el código, pero no reutilizarlo.
