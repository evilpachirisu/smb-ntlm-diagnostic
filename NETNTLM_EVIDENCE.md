# NetNTLM形式の追加表示

既存のコンソール表示に、観測したNetNTLMv1／NetNTLMv2形式の証跡を追加できます。**既定は無効**です。

```powershell
# Windows PowerShell
.\Start-SmbDiagnostic.ps1 -ShowNetNTLM
# Pythonから直接起動
.\.venv\Scripts\python.exe -m smbdiag --show-netntlm --port 8446
```

```sh
# Linuxなど
python3 -m smbdiag --show-netntlm --port 8446
```

オプションを付けなければ従来どおりの表示です。`--quiet`／PowerShellの `-Quiet` を併用すると、NetNTLM表示も含めて実行中のコンソール出力を抑制します。

## 追加される出力

通常のNTLM形式判定の次に、接続元IP・ポート・接続IDを付けて表示します。表記例の `<...>` は実際の値に置き換わります。

```text
[!] <IP>:<port> [id=<id>] NetNTLMv1: <user>::<domain>:<LM response hex>:<NT response hex>:<server challenge hex>
[!] <IP>:<port> [id=<id>] NetNTLMv2: <user>::<domain>:<server challenge hex>:<proof hex>:<blob hex>
```

NTLMv1-ESS候補は `NetNTLMv1 (ESS)` と表示します。既存の分類器がunknown／空応答と判断した場合や、同じ接続のType 2を観測していない場合は、追加表示しません。既存のUnknown理由や未判定表示は残ります。

ここで一般に「NetNTLMハッシュ」と呼ぶものは、観測したチャレンジ・レスポンスの組です。パスワードや保存済みのNTハッシュを取得する機能ではなく、認証応答の暗号学的正当性も検証しません。

## 出力経路

Impacket 0.13.1の `outputToJohnFormat` を再利用し、その接続で送信したType 2のchallengeと、受信Type 3から形式化します。分類は既存の `response_format` を使います。

追加データは専用のコンソール経路だけを通し、JSONL／テキストログのフィールドや内容は変更しません。認証成功やファイル共有を許可する機能も追加していません。制御文字とASCII以外の文字はJSON式のエスケープ表記にし、コンソールへの制御文字混入を防ぎます。

表示を有効にした標準出力にはユーザー名・ドメイン名・認証応答が含まれます。標準出力をリダイレクトした場合は、その出力先にも含まれます。本ツールのログファイルへ自動保存する機能はありません。

## 検証結果

macOS / Python 3.9 / Impacket 0.13.1で、全44件中42件成功、Windows専用2件スキップ。新規7件でv1／v2／ESS形式、既定非表示、quiet優先、Unknown・Type 2未観測時の非表示、ログ非保存、表示例外時の継続、実行時オプションを確認しました。実際の資格情報は使用していません。

結果：`validation/macos-netntlm-result.json`。Windows／Linux実機での実行は未確認です。
