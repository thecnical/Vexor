# Vexor file generator - writes all implementation files
import pathlib, os
ROOT = pathlib.Path('vexor')
CLI = ROOT / 'cli' / 'vexor'
def w(path, txt): p=pathlib.Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(txt,encoding='utf-8'); print(f'  wrote {p.name}')
