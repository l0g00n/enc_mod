Simple, fast and lightweight CLI data locking tool built in rust.  

## How to Use

```bash
# Build from source
# Build location: datalok/target/release/datalok
cd "download folder"/datalok
cargo build --release

# Example usage:
# datalok <file/folder> [-s] <-e | -d> [-r] [-p]

#  Flags:
#    -e Encryption 
#    -d Decryption 
#    -s Start a session
#    -r Recursively processes files in a directory
#    -p Prompted to type in a password

# Encrypt a file:
  datalok <file> -e
# Encrypt a file by entering a password:
  datalok <file> -e -p
# Decrypt a folder recursively:
  datalok <folder> -d -r
# Start a session:
  datalok -s
# Start a session by entering a password:
  datalok -s -p
```
**Session features include**:  
- Stores the password or password file for the duration of the session.
- Capable of encrypting or decrypting files from any location on the system.
- Uses the system file explorer when selecting files or folders to process.
```bash
# Example session usage:
#  <e | d> [-r]

#  Commands:
#    e | encrypt - Encryption
#    d | decrypt - Decryption
#    h | help - Shows all commands
#    exit - Exits the session
  
#  Flags:
#    -r Recursively processes files in a directory

# Encrypt a folder recursively:
  e -r
# Decrypt a folder recursively:
  decrypt -r 
```
***