# Contributing to Vexor

Thank you for your interest in contributing to Vexor!

## How to Contribute

### 1. Fork & Clone
```bash
git clone https://github.com/yourusername/vexor
cd vexor
```

### 2. Setup Dev Environment
```bash
cd cli
pip install -e ".[all]"
```

### 3. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 4. Make Changes
- Follow existing code style
- Add docstrings to new functions
- Test your changes

### 5. Submit PR
- Clear description of changes
- Reference any related issues

## Adding a New Scan Module

1. Create `vexor/cli/vexor/modules/your_module.py`
2. Inherit from `BaseScanner`
3. Implement `async def scan(self) -> list[Finding]`
4. Add to scanner screen module list

```python
from vexor.modules.base import BaseScanner, Finding

class Scanner(BaseScanner):
    MODULE_NAME = "your_module"
    MODULE_DESC = "Your module description"

    async def scan(self) -> list[Finding]:
        async with self:
            # Your scanning logic
            pass
        return self.findings
```

## Code Style
- Python 3.11+
- Type hints everywhere
- Async/await for all I/O
- Handle exceptions gracefully

## Legal
All contributions must be for legitimate security testing purposes only.
