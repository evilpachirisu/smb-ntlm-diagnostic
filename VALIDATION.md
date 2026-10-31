# NetNTLM証跡表示追加後の結果（2026-10-31）

`python verify_environment.py --output validation/macos-netntlm-result.json` を実行。**44件中42件成功、失敗・エラー0、Windows専用2件スキップ**です。新規7件も合成データだけで検証し、既存の診断・コンソール・ログのテスト37件を維持しました。Windows／Linux実機は未確認です。

追加仕様とテスト範囲は [NETNTLM_EVIDENCE.md](NETNTLM_EVIDENCE.md) を参照してください。以下は前回までの記録です。

# コンソール表示追加後の結果（2026-10-31）

`python verify_environment.py --output validation/macos-console-result.json` をmacOS / Python 3.9 / Impacket 0.13.1で実行しました。**37件中35件成功、失敗・エラー0、Windows専用2件スキップ**です。Windows／Linux実機では未実行です。

追加の表示テストは [CONSOLE.md](CONSOLE.md)、個別結果は `validation/macos-console-result.json` を参照してください。以下は前回レビュー時の記録です。

# 追加レビュー後の検証結果

2026-10-31、macOS / Python 3.9 / Impacket 0.13.1。

```text
python verify_environment.py --output validation/macos-result.json
Ran 28 tests
OK (skipped=2)
```

**成功26、失敗0、エラー0、Windows専用スキップ2。** 実行環境と個別結果は `validation/macos-result.json` に保存しています。前回の14件も含みます。スキップは成功件数に含めません。

- 純粋なNTLM形式解析、フラグ・ESS、不正バッファ、空応答。
- TCP接続・切断、timeout、途中EOF、過大フレーム。
- native SMB2およびSMB1形式bootstrap、Impacketクライアントの明示／既定ダイアレクト接続。
- 複数ダイアレクト、共通部分なし、DialectCount外データ、署名必須の提示記録。
- Type 1→2→合成Type 3、SPNEGO、v1／v1-ESS／v2候補、秘密情報非出力。
- DropSSP既定FalseとTrue、上流固定フラグとの一致。
- 全段階のログ順序、Type 2直後の切断、送信失敗時の誤った送信完了ログ防止。
- 使用中ポート、日本語・空白を含む出力パス、CLIの診断クライアント。
- 上流John変換・保存関数を呼ばないこと。

追加のCLIスモークでも、TCP/8446、`--drop-ssp`、診断クライアントの `--bootstrap`、Type 3到達、Ctrl+C停止を確認しました。`validation/cli-smoke-result.json` に結果を保存しています。

**未実行**：Windows 11実機、Windows専用2件（排他的bind／PowerShell起動口）、Windows上の全共通テスト、Windows CI、Windows Server 2022実相互運用。Windows向け手順・証跡保存方法は `WINDOWS_VALIDATION.md` に記載しています。

テストは実際の資格情報を使用しません。合成Type 3の形式に対する診断試験であり、有効な認証proof、実際のSSPIや署名・暗号化セッションを検証するものではありません。
