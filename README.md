# zkEVM-safe

zkEVM-safe is a command-line tool for analyzing EVM smart contract bytecode to detect incompatible opcodes for zkEVM. It supports both Foundry and Hardhat project structures and allows customization of unsupported opcodes.

## Motivation

This tool was developed to address the growing need for efficient zkEVM compatibility checks as more contracts are ported to this emerging technology.

## Features

- **Support for Foundry and Hardhat JSON structures**: Automatically detects and uses the appropriate JSON path style based on the structure of the file.
- **Customizable unsupported opcodes**: You can add or remove opcodes from the list of unsupported opcodes.
- **Verbose mode**: Provides detailed error messages.
- **General info mode**: Displays information about the current configuration and unsupported opcodes.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/sophon/zkevm-safe.git
    cd zkevm-safe
    ```

2. **Build the project**:
    ```bash
    cargo build --release
    ```

3. **Install the tool globally** (optional):
    ```bash
    cargo install --path .
    ```

## Usage

### Basic Usage

The tool can run on a folder on fetch code from a deployed contract.

To run the tool on a folder using Foundry settings:

```bash
./target/release/zkevm-safe --folder out
```

To run the tool on a folder using Hardhat settings:

```bash
./target/release/zkevm-safe --folder artifacts --artifacts hardhat
```

## Options

- **`--artifacts (-a)`**: Specify the project type. Default is `foundry`.
  - Example: `--artifacts foundry`
  - Example: `--artifacts hardhat`

- **`--folder (-f)`**: Specify the folder to scan for JSON files. Default is `out`.
  - Example: `--folder out`
  - Example: `--folder artifacts`

- **`--json-path (-j)`**: Specify the JSON path to the bytecode object. The tool detects this based on the project type, but you can override it.
  - Example: `--json-path deployedBytecode`
  - Example: `--json-path deployedBytecode.object`

To run the tool on a deployed contract:

```bash
./target/release/zkevm-safe --address 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 --rpc-url https://eth.llamarpc.com
```

## Common options

- **`--add-opcode (-A)`**: Add custom opcodes to the list of unsupported opcodes. You can add multiple opcodes by repeating the flag.
  - Example: `--add-opcode DELEGATECALL --add-opcode STATICCALL`

- **`--remove-opcode (-R)`**: Remove specific opcodes from the list of unsupported opcodes. You can remove multiple opcodes by repeating the flag.
  - Example: `--remove-opcode SELFDESTRUCT`

- **`--info (-i)`**: Display general information, including the list of unsupported opcodes.
  - Example: `--info`

- **`--verbose (-v)`**: Enable verbose mode to print detailed error messages to the console.
  - Example: `--verbose`

## Examples

### Check a folder using Foundry settings (default):

```bash
zkevm-safe --folder out
```

### Check using Hardhat settings:

```bash
zkevm-safe --folder artifacts --artifacts hardhat
```

### Add a custom opcode:

```bash
zkevm-safe --add-opcode DELEGATECALL
```

### Remove an opcode:

```bash
zkevm-safe --remove-opcode SELFDESTRUCT
```

### Get General Info:

```bash
zkevm-safe --info
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an Issue.

## Author
Sophon

## Acknowledgments
Inspired by the need to ensure compatibility of smart contracts with zksync zkEVM.