
import json
import click
from .verifier import verify_path

@click.group()
def cli():
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--public-key', type=click.Path(exists=True), help='Optional PEM public key to verify COSE signature')
@click.option('--details', is_flag=True, help='Include full manifest and diagnostics')
def verify(path, public_key, details):
    """Verify a file and print JSON result."""
    pem = None
    if public_key:
        with open(public_key, 'rb') as f:
            pem = f.read()
    res = verify_path(path, details=details, public_key_pem=pem)
    print(json.dumps(res.__dict__, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    cli()
