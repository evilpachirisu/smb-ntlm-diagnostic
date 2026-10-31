# 追加レビューの修正と制約

2026-10-31。前回版の既定動作を維持し、以下を変更しました。

| 指摘・調査結果 | 修正 | 検証 |
|---|---|---|
| DropSSP=False固定 | `--drop-ssp`／PowerShell `-DropSSP`。設定値を上流へ渡す | False時ESS維持、True時Type 2全フラグが上流定数と一致することを確認 |
| SMB1形式bootstrapを拒否 | 上流のSMB2 Negotiate生成をisSMB1=Trueで再利用 | Impacket SMBConnectionの既定接続、および合成クライアントのbootstrapで確認 |
| 0x0202以外への対応不足 | 提示したダイアレクト全体と選択結果を記録。上流対応の0x0202との共通部分を検査 | 複数提示／共通部分なし／DialectCount外のバイト混入 |
| Type 2生成と送信ログの混同 | メタデータを一時保留し、sendall後に確定 | 送信例外を注入し、Type 2送信完了が記録されないことを確認 |
| Session Setup受信が見えない | NTLM解析前の独立イベントを追加 | TCP→認証終了までの段階の順序を検証 |
| 接続失敗の切り分け不足 | protocol_version、stage、last_stage、local endpoint、win_errorを追加 | Type 2直後の切断／起動時bind失敗／クライアント側失敗段階 |
| SPNEGOメカニズムの完全一致要求 | 先頭NTLM＋後続メカニズムを許容 | 複数メカニズムのunwrap確認 |
| Windows未確認 | 実環境テスト実行器とWindows専用テスト・手順を追加 | Windows固有2件は本環境ではスキップ。成功扱いしない |

主な変更ファイルは `smbdiag/server.py`、`metadata.py`、`eventlog.py`、`__main__.py`、PowerShell起動スクリプトです。新規に `client.py`、`tests/test_review.py`、`verify_environment.py` を追加しました。上流パッケージのファイルは変更していません。

## Impacket本体との差分として残すもの

- 任意ポート待受とSMB2応答／Type 2生成は上流を再利用します。
- 共有、RPC、資格情報入力、認証成功は提供しません。既定ではJohn形式出力も行いませんが、追加の `--show-netntlm` 指定時のみコンソールにNetNTLM形式を表示します。Type 3はメタデータ解析後に意図的な失敗を返します。
- 標準ポート139／445は拒否し、既定はループバック8446。Windowsでは排他的bindを使用します。
- Type 2 challengeは接続ごとに乱数生成し、ログへ出しません。
- 上流の自由形式ログを破棄し、許可したメタデータだけを出力します。
- 不正フレームとcompoundを拒否します。SMB1はSMB2への初期移行のみ扱います。

## 未解決事項・制約

1. **Windows 11実機での確認は未実施**です。macOSでWindowsのOS情報やWinsockを偽装した結果を実機確認とは扱っていません。
2. **Windows Server 2022との実相互運用試験は未実施**です。Server 2022から本ツールへ接続する場合も、任意ポート指定可能なクライアントが必要です。
3. **SMB2.1／SMB3のサーバー対応はありません**。上流0.13.1サーバーの選択結果が0x0202であるため、これらしか提示しないクライアントはSTATUS_NOT_SUPPORTEDです。これを解消するにはダイアレクト別のプロトコル実装・適合試験が必要で、今回の最小改修には含めません。
4. 実際のWindows SSPIによる認証、署名必須クライアントの認証成立、Kerberos、暗号化、共有操作は未対応です。合成Type 3の到達はそれらの成立を意味しません。
5. ローカル診断クライアントは本ツール向けです。正当な認証proofを作らず、Windows Server 2022への認証評価用クライアントではありません。
6. TCP受付ログがない場合、サーバーのログだけではルーティング、FW、接続先間違いを区別できません。クライアントの失敗段階とOSエラーを併用します。
7. フラグや応答長による形式判定は推定です。ESSなしでもv2 blobが観測された場合はNTLMv2候補として扱います。DropSSPがNTLMv1を強制するとは判定しません。
8. `sendall`完了はローカルOSへの引渡しであり、相手アプリケーションによる処理成功の証明ではありません。


## コンソール表示の追加

`console.py`、EventLogの省略可能な表示オブザーバー、CLI `--quiet`、PowerShell `-Quiet`、表示テスト9件を追加しました。サーバー処理とNTLM分類器は変更していません。詳しくは [CONSOLE.md](CONSOLE.md) を参照してください。


## NetNTLM証跡の追加表示

既定無効の `--show-netntlm`／`-ShowNetNTLM` を追加しました。既存の形式推定とImpacketのフォーマッターを再利用し、専用表示経路へだけ渡します。JSONL／テキストログのスキーマと出力処理、認証拒否の動作は維持しています。詳しくは [NETNTLM_EVIDENCE.md](NETNTLM_EVIDENCE.md) を参照してください。
