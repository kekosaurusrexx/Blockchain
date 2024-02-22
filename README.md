# Python Blockchain with smart contracts

This is a simple proof of concept of a blockchain written in python.
It aims to implement a blockchain with mining, transactions, smart contracts and networking.
Written for a university project.

## Usage

Start the server script main.py.
If debug mode is enabled, following commands can be send with console.py:

- tt: send a test transaction (development only)
- stop: stop the server

## ToDos

- implement smart contracts
- implement automatic difficulty adjustment
- finish networking capabilitys
- add a requirements file
- change formatting of signature
- coin-balances and working transactions
- switch from single block files on disk to a database

## What it can do

- load & save chain as block-files locally
- proof of work with hashes and difficulty
- create correctly chained blocks
- validate the blockchain
- sign and verify data
- sign and verify transactions
- add transactions to blockchain
- mine in a seperate thread
- send and receive whole blockchains
