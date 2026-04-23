import socket
from dataclasses import asdict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from services.scanner_scapy import perform_arp_sweep

router = APIRouter()


def get_local_subnet() -> str:
    """Automatski detektuje lokalnu /24 mrežu."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        octets = local_ip.split(".")
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


class ScanRequest(BaseModel):
    target_subnet: str = Field(
        default_factory=get_local_subnet,
        description="CIDR opseg za skeniranje, npr. 192.168.1.0/24",
    )
    model_config = {
        "json_schema_extra": {
            "example": {"target_subnet": get_local_subnet()}  # ← automatski detektuje
        }
    }

@router.post("/scan/discovery")
async def run_discovery(request: ScanRequest):
    print(f"\n[DEBUG] Zahtev za skeniranje: {request.target_subnet}")

    try:
        devices = perform_arp_sweep(request.target_subnet)
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail="ARP sweep zahteva Administrator/root privilegije. Pokreni server kao admin.",
        )

    return {
        "status": "success",
        "target_subnet": request.target_subnet,
        "total_devices_found": len(devices),
        "devices": [asdict(d) for d in devices],  # ✅ dataclass → dict → JSON
    }