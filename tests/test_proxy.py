import requests
import asyncio
import websockets
import httpx
import logging
import ssl
from rich.console import Console

# Configure logging
logging.basicConfig(
    level="INFO",
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("test")
console = Console()

PROXY_HTTP_ADDR = "http://127.0.0.1:8080"
PROXY_HTTPS_ADDR = "https://127.0.0.1:8443"

async def test_http(name, url, host, path="/", expected_status=200):
    """Test HTTP/HTTPS proxying."""
    full_url = f"{url}{path}"
    log.info(f"Testing {name}: {full_url} (Host: {host})")
    
    try:
        # We use requests for simple HTTP/1.1 testing
        # We must ignore SSL verification for localhost self-signed cert
        response = requests.get(full_url, headers={"Host": host}, verify=False, timeout=10)
        
        if response.status_code == expected_status:
            log.info(f"[green]✔ {name} Passed[/green] (Status: {response.status_code})")
            return True
        else:
            log.error(f"[red]✘ {name} Failed[/red] (Status: {response.status_code} != {expected_status})")
            return False
    except Exception as e:
        log.error(f"[red]✘ {name} Error[/red]: {e}")
        return False

async def test_websocket(name, url, host, path="/"):
    """Test WebSocket proxying."""
    full_url = f"{url}{path}"
    log.info(f"Testing {name}: {full_url} (Host: {host})")
    
    ssl_context = None
    if url.startswith("wss"):
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        async with websockets.connect(
            full_url, 
            extra_headers={
                "Host": host,
                "Origin": "https://ws.postman-echo.com"
            }, 
            ssl=ssl_context,
            close_timeout=10,
            open_timeout=10
        ) as ws:
            await ws.send("Hello Raddy")
            response = await ws.recv()
            if response == "Hello Raddy":
                log.info(f"[green]✔ {name} Passed[/green] (Echoed: {response})")
                return True
            else:
                log.error(f"[red]✘ {name} Failed[/red] (Unexpected response: {response})")
                return False
    except Exception as e:
        log.error(f"[red]✘ {name} Error[/red]: {e}")
        return False

async def test_grpc_connectivity(name, url, host):
    """Test gRPC connectivity (via HTTP/2)."""
    full_url = f"{url}"
    log.info(f"Testing {name} (Connectivity): {full_url} (Host: {host})")
    
    try:
        client = httpx.AsyncClient(http2=True, verify=False)
        response = await client.post(
            full_url, 
            headers={"Host": host, "Content-Type": "application/grpc"}, 
            timeout=5
        )
        
        log.info(f"Response: {response.status_code} {response.headers}")
        
        if response.status_code not in [502, 504]:
             log.info(f"[green]✔ {name} Passed[/green] (Status: {response.status_code})")
             return True
        else:
             log.error(f"[red]✘ {name} Failed[/red] (Proxy Error: {response.status_code})")
             return False

    except Exception as e:
        log.error(f"[red]✘ {name} Error[/red]: {e}")
        return False
    finally:
        await client.aclose()

async def main():
    console.print("[bold blue]Starting Raddy Availability Tests...[/bold blue]")
    
    results = []

    # 1. HTTP -> httpbin
    results.append(await test_http("HTTP to HTTPBin", PROXY_HTTP_ADDR, "api.example.com", "/get"))
    
    # 2. HTTPS -> httpbin
    results.append(await test_http("HTTPS to HTTPBin", PROXY_HTTPS_ADDR, "secure.example.com", "/get"))
    
    # 3. WS -> Echo
    results.append(await test_websocket("WS Echo", "ws://127.0.0.1:8080", "ws.example.com", "/raw"))
    
    # 4. WSS -> Echo
    results.append(await test_websocket("WSS Echo", "wss://127.0.0.1:8443", "wss.example.com", "/raw"))
    
    # 5. gRPC Plain (HTTP/2)
    results.append(await test_grpc_connectivity("gRPC (Plain) Connectivity", PROXY_HTTP_ADDR, "grpc.example.com"))

    # 6. gRPC TLS
    results.append(await test_grpc_connectivity("gRPC (TLS) Connectivity", PROXY_HTTPS_ADDR, "grpcs.example.com"))

    console.print("\n[bold]Test Summary:[/bold]")
    if all(results):
        console.print("[bold green]All tests passed! 🚀[/bold green]")
    else:
        console.print(f"[bold red]{results.count(False)} tests failed.[/bold red]")

if __name__ == "__main__":
    # Disable warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    asyncio.run(main())
