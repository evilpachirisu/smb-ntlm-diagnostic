# SMB / NTLM Diagnostic

**Windows · Python 3 · Impacket 0.13.1**

SMB/NTLMの交渉を、コンソールとログで確認する診断ツール。
[DivertTCPconn](https://github.com/Arno0x/DivertTCPconn) と併用し、**TCP/445 → TCP/8446** へ転送して使う構成を想定しています。

```text
SMB client ── :445 ── DivertTCPconn ── :8446 ── SMB Diagnostic
```

## Quick start

Python 3.10〜3.13。Windows PowerShellで実行します。

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\Start-SmbDiagnostic.ps1 -BindAddress 0.0.0.0 -Port 8446
```

別の**管理者PowerShell**で、DivertTCPconnの配置先から実行します。

```powershell
.\divertTCPconn.exe 445 8446
```

クライアントはこのWindowsホストの**445**へ接続します。リスナーは受信用NICで待ち受けるため、上記では `0.0.0.0` を指定しています。

## Options

| PowerShell | 動作 |
|---|---|
| `-ShowNetNTLM` | NetNTLMv1/v2形式の証跡を追加表示 |
| `-DropSSP` | 上流のDropSSP設定を有効化 |
| `-Quiet` | コンソール表示を抑制 |

接続状況・Dialect・ESS・NTLM形式をリアルタイム表示。ログは `logs/events.jsonl` / `logs/events.txt`。NetNTLM証跡の表示は既定OFFで、ログには保存しません。

## Docs

[詳細ガイド](GUIDE.md) · [コンソール表示](CONSOLE.md) · [NetNTLM証跡](NETNTLM_EVIDENCE.md) · [実装・制約](REVIEW_CHANGES.md) · [検証結果](VALIDATION.md)

SMB 2.0.2対応。診断後は認証失敗を返します。Windows実機・DivertTCPconn併用は未検証です。
