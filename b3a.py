import click
import socket

import naiveAuth.verifier
import naiveAuth.prover
import proposedAuth.verifier
import proposedAuth.prover

@click.group
@click.version_option()
@click.help_option()
def cli():
    pass

# Set Up the Verifier 
@cli.command()
@click.option('-h', '--host', required=True, type=click.STRING, default="127.0.0.1")
@click.option('-p', '--port', type=click.INT, default=9000)
@click.option('-N', '--naive', 'naive', flag_value=True)
@click.argument('input', type=click.Path(allow_dash=True), nargs=-1)
def listen(input, host, port, naive):
    if naive:
        v = naiveAuth.verifier.Verifier(input, isPath=True)
    else:
        v = proposedAuth.verifier.Verifier(input, isPath=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        click.echo(f"Watching for Provers on {(host, port)}")

        conn, addr = s.accept()
        with conn:
            click.echo(f"Connected by {addr}")
            
            click.echo(f"Issuing Challenge...")

            if naive: 
                challengeIdx = v.issueChallenge()
            else:
                challengeIdx, proofLength = v.issueChallenge()
                proofLengthSize = proofLength.bit_length()
                extraByte = 0 if proofLengthSize % 8 == 0 else 1
                requiredByteLength = proofLengthSize // 8 + extraByte
                proofLengthBytes = proofLength.to_bytes(requiredByteLength, byteorder='big')
            
            challengeSize = challengeIdx.bit_length()
            extraByte = 0 if challengeSize % 8 == 0 else 1
            requiredByteLength = challengeSize // 8 + extraByte
            challengeIdxBytes = challengeIdx.to_bytes(requiredByteLength, byteorder='big')

            if naive:
                conn.send(bytes([1])) # Flag sent to the prover indicating that naive authentication is used
                conn.send(challengeIdxBytes)
            else:
                conn.send(bytes([0])) # Flag sent to the prover indicating that naive authentication is NOT used
                conn.send(challengeIdxBytes)

                # Wait for flag from prover indicating that challengeIdxBytes was received
                # Note: The issue here is that the challengeIdxBytes length is variable. Thus on the prover's side,
                # it is hard to distinguish the challengeIdxBytes from the proofLengthBytes. As a workaround, use the
                # fact that conn.recv is blocking and wait for the prover to respond before sending the proofLengthBytes
                challengeIdxBytesRecv = int.from_bytes(conn.recv(1024), byteorder='big') 
                
                # If the response flag is not 1 (True), then something went wrong. Return to abort.
                if not challengeIdxBytesRecv:
                    click.echo("An unexpected error occured!")
                    return

                conn.send(proofLengthBytes)
            
            awaiting_proof = True

            while awaiting_proof:
                # If naive authentication is not used, then the proof will usually be longer than
                # 1024 bytes. The required buffer size can be calculated as proofLength * 33
                data = conn.recv(1024 if naive else (proofLength * 33))
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
@click.argument('input', type=click.Path(allow_dash=True), nargs=-1)
def connect(input, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        click.echo(f"Connected to {(host, port)}")

        # Determine if the verifier wishes to use naive authentication
        naive = int.from_bytes(s.recv(1), byteorder='big')

        if naive:
            p = naiveAuth.prover.Prover(input, isPath=True)
        else:
            p = proposedAuth.prover.Prover(input, isPath=True)
        
        challengeIdxBytes = s.recv(1024)

        if not naive:
            # If naive authentication is not used, prover needs to send
            # a response indicating that the challengeIdxBytes was received,
            # before the verifier will send the proofLengthBytes.
            # See the comments under listen() for more info
            s.send(bytes([1]))
            proofLengthBytes = s.recv(1024)

        click.echo(f"Received Challenge from {(host, port)}")

        challengeIdx = int.from_bytes(challengeIdxBytes, byteorder='big')

        if naive:
            proof = p.respondToChallenge(challengeIdx)
        else:
            proofLength = int.from_bytes(proofLengthBytes, byteorder='big')
            proof = p.respondToChallenge(challengeIdx, proofLength)
        
        click.echo(f"Sending Proof to {(host, port)}")
        s.send(proof)

        res = s.recv(1024).decode("utf-8")

    click.echo(f"Received from {(host, port)}: {res}!")