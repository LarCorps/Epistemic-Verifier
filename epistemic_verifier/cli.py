import json
import click
from .verifier import verify_path
from enum import Enum

@click.group()
def cli():
    pass

def _json_safe(obj):
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value if hasattr(obj, "value") else obj.name
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_json_safe(x) for x in obj]
    return str(obj)

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--public-key', type=click.Path(exists=True), help='Optional PEM public key to verify COSE signature')
@click.option('--details', is_flag=True, help='Include full manifest and diagnostics')
@click.option('--analog-csv', type=click.Path(), help='Write per-frame analog signals to CSV')
@click.option(
    '--require-aocv/--no-require-aocv',
    default=True,
    show_default=True,
    help='Require AOCV camera sensor challenge to be present + valid (photos + videos)',
)
def verify(path, public_key, details, require_aocv, analog_csv):
    """Verify a file and print JSON result."""
    pem = None
    if public_key:
        with open(public_key, 'rb') as f:
            pem = f.read()
    res = verify_path(
        path,
        details=details,
        public_key_pem=pem,
        require_aocv=require_aocv,
        analog_csv_path=analog_csv
    )
    print(json.dumps(_json_safe(res.__dict__), indent=2, ensure_ascii=False))

if __name__ == '__main__':
    cli()
