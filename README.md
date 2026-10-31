# SMB/NTLMネゴシエーション診断ツール（コンソール表示対応）

Impacket **0.13.1** のSMB2エンジンを使う、認証メタデータを記録する診断リスナーです。既定は `127.0.0.1:8446`。Windows標準SMBサービスを停止する必要はありません。共有、RPC、認証成功後のセッションは提供しません。Type 3を観測したら意図的に認証失敗を返します。

## 導入と起動（Windows 11 / PowerShell）

Python 3.10〜3.13を想定しています。配布フォルダーへ移動して実行してください。

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\Start-SmbDiagnostic.ps1
```

Pythonから直接起動することもできます。

```powershell
.\.venv\Scripts\python.exe -m smbdiag --bind 127.0.0.1 --port 8446
```

許可された別ホストから接続する場合は、その演習ネットワークのローカルIPv4アドレスを明示します。必要なファイアウォール許可は演習環境の設定に合わせてください。

```powershell
.\Start-SmbDiagnostic.ps1 -BindAddress 192.0.2.10 -Port 8446 -LogDirectory .\logs\exercise01
```

`192.0.2.10` は記載例です。実際にホストへ割り当てたアドレスへ置き換えます。Ctrl+Cで終了します。139／445は拒否し、使用中ポートへのbind失敗はエラーイベントに記録します。ポート転送、標準SMBの設定変更、ファイアウォール変更は行いません。

ログ形式は `-Format both`（既定）、`jsonl`、`text` から選べます。Python CLIには `--format`、`--jsonl`、`--text`、`--idle-timeout`（既定15秒、上限300秒）があります。ログは追記なので、演習ごとに出力先を変えると整理できます。

## 接続検証とテスト

テストは標準ライブラリの `unittest` を使用します。実際の資格情報や外部サーバーは不要です。TCPテストはループバックの空きポートをOSに選択させます。

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
# TCPだけ
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_diagnostic.py -k tcp_only -v
# SMBネゴシエーションだけ
.\.venv\Scripts\python.exe -m unittest discover -s tests -k smb_negotiate -v
# NTLMおよび秘密情報の非出力
.\.venv\Scripts\python.exe -m unittest discover -s tests -k ntlm_and_no_secret_output -v
```

起動中リスナーへのSMB2ネゴシエーションだけを確認する例（ログの `smb_negotiate` を確認）：

```powershell
.\.venv\Scripts\python.exe -c "from impacket.smbconnection import SMBConnection; c=SMBConnection('SMBDIAG','127.0.0.1',sess_port=8446,preferredDialect=0x0202); print(hex(c.getDialect())); c.close()"
```

クライアント側にも任意ポートを指定できるSMBクライアントが必要です。`\\host:8446\share` というUNC表記を接続手順として使わないでください。NTLM段階までの検証には、同梱テストがraw NTLMおよびSPNEGOの合成メッセージを送信します。実際のWindowsクライアントがType 3を送らず切断する場合も、到達した段階と切断を記録します。OSやポリシーの詳細原因はサーバー側の観測だけでは確定できません。

## ログの読み方

既定の出力先は `logs/events.jsonl` と `logs/events.txt` です。タイムスタンプはUTCのISO 8601形式。接続ごとの `connection_id`、接続元IP／ポートでイベントを対応付けます。`connect.timestamp` が接続時刻です。

| イベント | 内容 |
|---|---|
| `listen` / `stop` | 待受開始／停止 |
| `connect` / `disconnect` | 接続元、切断理由 |
| `smb_negotiate_received` | Negotiate受信。SMB1形式bootstrapとSMB2を区別 |
| `smb_negotiate` | 応答送信完了、NTSTATUS、提示／選択ダイアレクト、SMB security mode |
| `smb_session_setup` | Session Setup受信。NTLM解析前に記録 |
| `ntlm` | 方向、Type 1／2／3、フラグ名・16進値、ESSビット |
| `session_result` | 終了応答送信後の診断上の結果、または認証段階の入力エラー |
| `error` | 固定の理由コード、例外クラス名、存在すればOSエラー番号 |

Type 3のログには `response_format`、`classification_basis`、LM／NT応答長、`negotiated_ess` も含みます。`ess` はそのメッセージのビット、`negotiated_ess` は観測したType 1とType 2の両方にESSがあるかを表します。Type 1／2がそろわない場合は `null` です。

| `response_format` | 推定条件 |
|---|---|
| `NTLMv1` | NT応答24バイト、ESS交渉なし、Type 3にもESSなし |
| `NTLMv1-ESS` | NT応答24バイト、LM応答24バイトの後半16バイトがゼロ、ESS交渉あり、Type 3にもESSあり |
| `NTLMv2` | NT応答内のv2 blobヘッダー、予約領域、境界内のAVペアと終端を確認 |
| `empty_or_anonymous` | NT応答なし。匿名であることまでは断定しない |
| `unknown` | 不足・不整合・その他の形式 |

これらは**形式の推定**です。応答の暗号学的正当性や実際に使用されたパスワードは検証しません。24バイトという長さだけではNTLMv1を確定できず、ESSビットだけでもNTLMv2とは判定できません。認識できない、古い短縮ヘッダー、不正なセキュリティバッファはエラーまたはunknownとして扱います。

主なステータス：

- `0x00000000`：SMBネゴシエーション成功。
- `0xc0000016`：Type 2送信時の `STATUS_MORE_PROCESSING_REQUIRED`。次のメッセージ待ちで正常です（Type 2イベントで確認）。
- `0xc000006d`：`STATUS_LOGON_FAILURE`。本ツールのType 3観測後の意図的な応答で、資格情報の正誤を意味しません。
- `0xc000000d`：不正な認証トークンなど。
- `0xc00000bb`：共通ダイアレクトなし。

切断理由は `diagnostic_complete`、`peer_closed`、`timeout`、`truncated_frame`、`connection_reset`、`invalid_protocol`、`server_shutdown` などです。`peer_closed` は観測された終了であり、クライアント内部の理由は不明です。例外本文やトレースバックは出力しません。

## 保存しないデータと構成

パスワード／ハッシュの入力オプションはありません。認証応答、challenge、セッションキー、ユーザー名、ドメイン名、端末名、AVペアの値、パケット本体はJSONL／テキストログに保存しません。`--show-netntlm` を明示した場合だけ、NetNTLM証跡をコンソールに追加表示します。プロトコル解析に必要な受信バイトは処理中のメモリだけに存在します。

Type 3はImpacketの認証処理へ渡す前に遮断します。上流の自由形式ログも転送しません。ログ出力クラスは許可フィールドだけを受け付け、JSONL・テキストとも制御文字をエスケープします。IPや時刻は要件に従って保存します。

- `smbdiag/server.py`：Impacketの待受基底クラス、SMB2処理・フック、接続状態。
- `smbdiag/metadata.py`：NTLMメタデータ解析。ファイルI/Oなし。
- `smbdiag/eventlog.py`：ログ出力。プロトコル処理なし。
- `smbdiag/__main__.py`：CLIと終了処理。

SMB1形式NegotiateからのSMB2移行と、SMB2ダイアレクト0x0202の直接接続、IPv4、単一要求のNEGOTIATE／SESSION_SETUP、raw NTLM／NTLMを先頭メカニズムとするSPNEGOを対象とします。SMB1の認証・共有処理、SMB2.1／SMB3、複合要求、Kerberos、共有操作、署名付き認証の成立は対象外です。`--drop-ssp`（PowerShellでは `-DropSSP`）で、上流の固定Type 2フラグを選択できます。既定はFalseです。

## ソース調査・検証結果

詳細は [SOURCE_REVIEW.md](SOURCE_REVIEW.md)、[VALIDATION.md](VALIDATION.md) を参照してください。上流ソースへパッチを当てず、依存版を固定しています。非公開メソッド `_ntlm_auth` はType 1入力時のType 2生成に限定して再利用しているため、依存バージョンが違えば起動を拒否します。

NetNTLM追加表示対応後、macOS / Python 3.9で44件中42件成功、Windows専用2件スキップです。Windows 11実機での実行は未実施です。同梱のGitHub ActionsはWindows runner／Python 3.10〜3.13で同じテスト・結果JSON保存とPowerShell構文チェックを実行するための設定で、実行結果はまだありません。リポジトリへ配置する場合は、このフォルダーをリポジトリルートにしてください。


## 追加レビュー後の利用方法（2026-10-31）

外部接続の切り分け、Windows実機での確認、未解決事項は [WINDOWS_VALIDATION.md](WINDOWS_VALIDATION.md) と [REVIEW_CHANGES.md](REVIEW_CHANGES.md) を参照してください。

診断用クライアントを追加しました。実在するユーザーやパスワードを入力せず、無効な合成Type 3を送ります。本ツールへ接続し、意図した認証失敗まで到達すれば終了コード0を返します。

```powershell
# 起動中の本ツールへTCP→SMB2→Type 1→Type 2→合成Type 3
.\.venv\Scripts\python.exe -m smbdiag.client --host 127.0.0.1 --port 8446
# SMB1形式の初期Negotiate→SMB2への移行も検証
.\.venv\Scripts\python.exe -m smbdiag.client --host 127.0.0.1 --port 8446 --bootstrap
# 上流DropSSP動作で比較（別途リスナーを再起動）
.\Start-SmbDiagnostic.ps1 -DropSSP
# 実行環境と個別テスト結果を保存
.\.venv\Scripts\python.exe verify_environment.py --output validation\windows-result.json
```

`stage` と `last_stage` が最終到達段階を示します。Type 2およびNegotiate応答の「送信」は `sendall` が完了した意味であり、相手が受信・処理したことまでは保証しません。送信失敗時は送信完了イベントを記録せず、例外と直前の段階を残します。Windowsでは `os_error` に加えて `win_error` を記録します。接続受付には `local_ip`／`local_port` もあります。

既存イベント名・既定ポート・既定のESS動作・JSONL／テキスト出力は維持しています。受信イベントとメタデータが追加されたため、ログの行番号に依存した処理は更新してください。


## リアルタイム表示とquiet

既定で起動設定、接続元IP・ポート、SMB Dialect、Type 2のESS、Type 3分類、切断・エラーをコンソール表示します。NTLM判定は `>>> NTLMv2 detected (format estimate) <<<` の形式で強調します。Unknownの理由とType 3未解析時の未判定も表示します。JSONL・テキストログの内容は変えていません。

`python -m smbdiag --quiet`、PowerShellでは `.\Start-SmbDiagnostic.ps1 -Quiet` で実行中表示を抑制できます。使い方・表示例・検証結果は [CONSOLE.md](CONSOLE.md) を参照してください。


## NetNTLM形式の証跡表示（任意）

`python -m smbdiag --show-netntlm`、PowerShellでは `.\Start-SmbDiagnostic.ps1 -ShowNetNTLM` を指定すると、従来の出力にNetNTLMv1／NetNTLMv2形式の証跡を追加します。既定は無効、`--quiet`／`-Quiet` が優先です。JSONL・テキストログへは追加しません。詳細は [NETNTLM_EVIDENCE.md](NETNTLM_EVIDENCE.md) を参照してください。
