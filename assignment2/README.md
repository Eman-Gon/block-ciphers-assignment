
```markdown
# Block Ciphers Assignment

CSC 321 - Introduction to Computer Security

## Setup

Install required packages:
```bash
pip install pycryptodome pillow matplotlib numpy
```

## How to Run

### Task 1 & 2: Encrypt Image and Bit-Flipping Attack
```bash
python3 block_ciphers.py
```

**Expected Output:**
```
Saved: ecb_encrypted.bmp and cbc_encrypted.bmp
Task 2: CBC Bit-Flipping Attack Demo
Before attack: verify() = False
After attack:  verify() = True
Attack worked! Got admin access.
```

This creates:
- `ecb_encrypted.bmp` - Shows visible mustang pattern (insecure)
- `cbc_encrypted.bmp` - Looks random (secure)

### Optional: Generate Demo Images
```bash
python3 create_artifacts.py
```

Creates checkerboard pattern and avalanche effect visualization in `images/` folder.

### Optional: Performance Graphs
```bash
python3 make_graphs.py
```

Creates `images/performance_comparison.png` showing AES vs RSA performance.

## Files

- `block_ciphers.py` - Main implementation (Tasks 1 & 2)
- `create_artifacts.py` - Demo visualizations
- `make_graphs.py` - Performance comparison graphs
- `report.md` - Assignment writeup
- `mustang.bmp` - Original test image


## Tasks Completed

- Task 1: ECB and CBC encryption implementation
- Task 2: CBC bit-flipping attack demonstration
- Task 3: AES vs RSA performance analysis
```