# リアルタイムコンソール表示

既定で、起動設定、接続元IP・ポート、SMB Dialect、送信済みType 2のESS、Type 3の形式推定、切断・エラーを即時表示します。各行に接続元ポートと接続IDの先頭8桁を付けます。内部状態は省略していない接続IDをキーに管理するため、同じIPや再利用されたポートでも判定状態が混ざりません。

```powershell
# Windows PowerShell（導入手順はREADME）
.\Start-SmbDiagnostic.ps1 -BindAddress 0.0.0.0 -Port 8446
# 表示だけを抑制。JSONL・テキスト・終了コードは維持
.\Start-SmbDiagnostic.ps1 -Quiet
```

```sh
# Linuxなどのターミナル
python3 -m smbdiag --bind 0.0.0.0 --port 8446
python3 -m smbdiag --quiet
```

`--drop-ssp`／PowerShellの `-DropSSP` も従来どおり使用できます。`--quiet` はサーバーの実行中表示を抑制します。引数エラーや `--help` は通常のCLI出力です。別コマンドで起動する診断クライアントの出力には影響しません。

表示例（接続IDは例）：

```text
[*] SMB Diagnostic Server started
[*] Listening: 0.0.0.0:8446
[*] DropSSP: Disabled
[+] 192.168.56.10:62069 [id=aaaaaaaa] Connected
[*] 192.168.56.10:62069 [id=aaaaaaaa] SMB 2.0.2
[*] 192.168.56.10:62069 [id=aaaaaaaa] NTLM Type 2 sent (ESS: ON)
[+] 192.168.56.10:62069 [id=aaaaaaaa] >>> NTLMv2 detected (format estimate) <<<
[-] 192.168.56.10:62069 [id=aaaaaaaa] Disconnected (diagnostic complete)
```

NTLMv1-ESSは `NTLMv1 (ESS)` と表示します。既存分類結果がunknownや空応答の場合は `>>> Unknown (理由) <<<` を表示します。例：`ESS flags inconsistent`、`Type 1/2 metadata missing`、`empty NT response; anonymous not established`。Type 3の分類イベントを受け取らず切断した場合は `NTLM version undetermined: Type 3 not parsed` とし、バージョンを推定しません。不正なType 3が解析できなかった場合も、この未判定表示になります。

色・ANSI制御・特殊文字に依存せず、ASCIIだけで判定を目立たせます。既定ではユーザー名、ドメイン名、応答、challenge、ハッシュ、例外本文を表示しません。`--show-netntlm` を明示した場合の追加証跡表示は [NETNTLM_EVIDENCE.md](NETNTLM_EVIDENCE.md) を参照してください。表示する理由も固定の対応表を使います。詳細なプロトコル情報は従来どおりログで確認します。

## 実装と検証

`smbdiag/console.py` がイベントの表示だけを担当します。既存の分類器を呼び直したり、応答長から再判定したりしません。`EventLog` は従来のログを書き終えてからオブザーバーへイベントのコピーを渡します。コンソールの切断・書込失敗はログ保存や診断処理を止めません。

ログのフィールド・JSONL・テキスト書式、プロトコル処理、分類器、依存関係は変更していません。固定時刻の同一イベントで、表示の有無にかかわらず両ログがバイト単位で一致することをテストしています。

2026-10-31、macOS / Python 3.9 / Impacket 0.13.1で **37件中35件成功、Windows専用2件スキップ**。既存28件も含みます。追加9件は、表示項目、unknown理由、並行接続、秘密情報・制御文字非出力、ログ不変、表示失敗、実接続表示、quiet時の正常診断／起動失敗を対象とします。結果は `validation/macos-console-result.json` に保存しています。

Windows PowerShell／Linuxで動かせる標準ライブラリのみの実装ですが、両環境での実行は本環境では未実施です。実機では次のコマンドで検証してください。

```powershell
.\.venv\Scripts\python.exe verify_environment.py --output validation\windows-console-result.json
```

```sh
python3 verify_environment.py --output validation/linux-console-result.json
```
