# Installation
1. Create a virtual environment within the root folder using `python -m venv ENV_NAME` where ENV_NAME is the filepath where you would like to create the virtual environment

2. Activate the virtual environment:

    > Windows: `ENV_NAME/Scripts/activate`

    > MacOS: `source ENV_NAME/bin/activate`

3. Install dependencies using `pip install -r requirements.txt`

4. Install the CLI using `pip install --editable .`

# Running the CLI
## Run with defaults
By default, the CLI listens on `127.0.0.1` *(localhost)* on port `9000` in the secure authentication mode.

As a Verifier, to start listening for Provers for files FILE_1 and FILE_2:

> `b3a listen FILE_1 FILE_2`
As a Prover, to provide proof for files FILE_1 and FILE_2:

> `b3a connect FILE_1 FILE_2`

## Specifying Options

Specifying a host, where HOST_NAME refers to the ip address or dns name you would like to use:

> `b3a listen -h HOST_NAME FILE_1 FILE_2`

> `b3a connect -h HOST_NAME FILE_1 FILE_2`

Specifying a port:

> `b3a listen -p PORT FILE_1 FILE_2`

> `b3a connect -p PORT FILE_1 FILE_2`

Using in naive mode:

> `b3a listen -N FILE_1 FILE_2`

> `b3a connect -N FILE_1 FILE_2`