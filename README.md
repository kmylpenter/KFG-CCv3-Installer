# KFG CCv3 Installer

Instalator Continuous Claude v3 z automatyczną migracją CCv2/KFG.

## Flow

1. Sprawdza/instaluje zależności (git, python, node, docker, uv, claude)
2. Instaluje hooki globalnie do `~/.claude/hooks/` (raz)
3. Pyta o folder projektów (np. `D:\Projekty`)
4. Skanuje wszystkie podfoldery i wykrywa CCv2/CCv3/Clean
5. Migruje CCv2→CCv3 gdzie potrzeba (archiwizacja `logs/`, `VALIDATION*.md`)
6. Opcjonalne klonowanie `opc/` do wybranych projektów
7. Raport końcowy ze statystykami

## Użycie

```powershell
powershell -ExecutionPolicy Bypass -File install-ccv3.ps1
```

## Detekcja projektów

| Typ | Wskaźniki |
|-----|-----------|
| CCv3 | `opc/` lub `thoughts/shared/handoffs/` |
| CCv2/KFG | `logs/CONTINUITY.md`, `logs/STATE.md`, `.log-file-genius/` |
| Clean | brak wskaźników CC |

## Wymagania

- Windows 10/11
- PowerShell 5.1+
- Git
- Python 3.11+
- Node.js 18+
- Docker Desktop
- uv (Python package manager)
- Claude Code CLI

## Powiązane repozytoria

- [Continuous-Claude-v3](https://github.com/parcadei/Continuous-Claude-v3) - oficjalne CCv3
- [Continuous-Claude-v3-Mirror](https://github.com/kmylpenter/Continuous-Claude-v3-Mirror) - backup
- [KFG-CCv2-Installer-Stable](https://github.com/kmylpenter/KFG-CCv2-Installer-Stable) - poprzednia wersja (CCv2)
