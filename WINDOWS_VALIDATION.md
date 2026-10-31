# Windows 11実機での検証と外部接続の切り分け

現時点でWindows 11／Server 2022実機の結果はありません。以下は実機で再現し、結果を取得するための手順です。

## 1. 導入・自動検証

ZIPを展開し、smb-ntlm-diagnosticフォルダー内のPowerShellで実行します。

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe verify_environment.py --output validation\windows-result.json
```

実行器はOS・build・Python・Impacket版、個々のテストのpassed／failed／error／skippedを保存します。失敗は終了コード1。Windows専用テストはWindows以外でskippedになります。`windows_11_tests_passed` はWindows 11のworkstation buildでスキップ・失敗なしにテストを実行した場合だけtrueです。Server 2022実相互運用はこの自動テストに含めず、`server2022_interoperability` は `not_run` のままです。

Windows専用の2項目は、SO_EXCLUSIVEADDRUSEによる二重bindの拒否とPowerShellエントリーポイントの標準ポート拒否です。他に日本語・空白を含むログパス、使用中ポートのOSエラー、サブプロセスからの診断クライアント接続を全OSで実行します。

## 2. 同一ホスト上の確認

一つ目のPowerShell：

```powershell
.\Start-SmbDiagnostic.ps1 -BindAddress 127.0.0.1 -Port 8446
```

二つ目のPowerShell：

```powershell
.\.venv\Scripts\python.exe -m smbdiag.client --host 127.0.0.1 --port 8446
.\.venv\Scripts\python.exe -m smbdiag.client --host 127.0.0.1 --port 8446 --bootstrap
```

クライアント出力の最終段階が `ntlm_type3_to_finish`、statusが `0xc000006d`、expected_diagnostic_rejectionがtrueなら、本ツールの診断フロー完了です。ユーザー資格情報の誤りを意味しません。クライアント失敗時の終了コードは1です。

## 3. 演習ネットワークからの確認

リスナー側Windows 11では、演習用NICのローカルIPv4アドレスを明示して起動します。

```powershell
# 192.0.2.10を実際のローカルIPv4へ置換
.\Start-SmbDiagnostic.ps1 -BindAddress 192.0.2.10 -Port 8446 -LogDirectory .\logs\remote01
Get-NetTCPConnection -LocalPort 8446 -State Listen
```

Server 2022などの許可された接続元に本ツールを配置し、依存をインストールしたPythonから診断クライアントを起動します。

```powershell
Test-NetConnection -ComputerName 192.0.2.10 -Port 8446
.\.venv\Scripts\python.exe -m smbdiag.client --host 192.0.2.10 --port 8446
```

実行するクライアントは接続元でType 1と合成Type 3を組み立てます。Windows SSPIを使用する試験ではありません。Windows標準SMBによる検証や実在アカウントでの認証成立は別の試験として区別してください。標準SMBサービスの停止や445からの転送は不要です。

## 4. 最終到達段階の対応

| 証跡 | 次に確認すること |
|---|---|
| listenイベントなし | bind先アドレス、Python／Impacket版、起動ログ、portの使用中状態 |
| listenあり、connectなし | ループバックに限定していないか、接続先IP・ポート、FW、経路、クライアント側TCPエラー |
| tcp_acceptedまで | SMBを送っているか。Test-NetConnectionはTCPだけなので、ここで切断するのは正常 |
| smb_negotiate_receivedまで | 不正要求、ダイアレクト提示、送信時例外。no_common_dialectなら0x0202なし |
| smb_negotiate_sentまで | クライアントが選択ダイアレクトや認証メカニズムを許容するか |
| smb_session_setup_receivedまで | NTLM／SPNEGOの形式、先頭メカニズムがNTLMか |
| ntlm_type1_receivedまで | Type 2生成エラーまたは送信エラー |
| ntlm_type2_sentまで | クライアントのローカルポリシー、署名要件、NTLM許可、接続元側のイベント。サーバーだけでは確定不可 |
| ntlm_type3_received→authentication_finished | 診断完了。意図した拒否であり資格情報検証はしていない |

ログはUTCです。Windowsでは `win_error` を確認します。例として10048はアドレス使用中、10013はアクセス拒否、10061はクライアントからの接続拒否、10054はリセットです。これらは原因候補であり、番号だけでFWやポリシーを断定しません。

## 5. 提出する証跡

`validation/windows-result.json` と対象接続のJSONL／テキストログを使用してください。認証応答のパケットキャプチャや実際の資格情報は本ツールの証跡に不要です。Server 2022での接続元／リスナー双方のOS build、実施したコマンド、到達段階を別途記録し、未実施の試験は未実施のまま残してください。
