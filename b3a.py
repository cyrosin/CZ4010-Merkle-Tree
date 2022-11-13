import click
import socket
import sys

from naiveAuth.verifier import Verifier
from naiveAuth.prover import Prover

@click.group
def cli():
    pass

@cli.command()
def test():
    click.echo("Hello World!")

# Set Up the Verifier 
@cli.command()
@click.option('-h', '--host', required=True, type=click.STRING, default="127.0.0.1")
@click.option('-p', '--port', type=click.INT, default=9000)
@click.argument('input', type=click.Path(allow_dash=True), nargs=1)
def listen(input, host, port):
    v = Verifier(input, isPath=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        click.echo(f"Watching for Provers on {(host, port)}")

        conn, addr = s.accept()
        with conn:
            click.echo(f"Connected by {addr}")
            
            click.echo(f"Issuing Challenge...")
            challengeIdx = v.issueChallenge()
            challengeSize = challengeIdx.bit_length()
            extraByte = 0 if challengeSize % 8 == 0 else 1
            requiredByteLength = challengeSize // 8 + extraByte
            challengeIdxBytes = challengeIdx.to_bytes(requiredByteLength, byteorder='big')
            conn.send(challengeIdxBytes)
            
            awaiting_proof = True

            while awaiting_proof:
                data = conn.recv(1024)
                if data:
                    awaiting_proof = False
            click.echo(f"Received Proof from {addr}")
            
            authenticated = v.verify(data)

            if authenticated:
                click.echo(f"Prover at {addr} provided a valid proof!")
                conn.send(b"Verified")
            else:
                click.echo(f"Prover at {addr} failed to provide a valid proof")
                conn.send(b"Unverified")

@cli.command()
@click.option('-h', '--host', required=True, type=click.STRING, default="127.0.0.1")
@click.option('-p', '--port', type=click.INT, default=9000)
@click.argument('input', type=click.Path(allow_dash=True), nargs=1)
def connect(input, host, port):
    p = Prover(input, isPath=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        click.echo(f"Connected to {(host, port)}")
        
        challengeIdxBytes = s.recv(1024)
        click.echo(f"Received Challenge from {(host, port)}")

        challengeIdx = int.from_bytes(challengeIdxBytes, byteorder='big')
        proof = p.respondToChallenge(challengeIdx)
        print(len(proof))
        
        click.echo(f"Sending Proof to {(host, port)}")
        s.send(proof)

        res = s.recv(1024).decode("utf-8")

    click.echo(f"Received from {(host, port)}: {res}!")