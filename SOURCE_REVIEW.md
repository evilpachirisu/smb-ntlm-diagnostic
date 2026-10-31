# Impacket 0.13.1 ソース調査と実装比較

調査日：2026-10-30。PyPI配布の `impacket==0.13.1` を作業用venvへインストールし、インストールされたソースを直接確認しました。元々ホストに入っていた0.13.0は使用していません。

参照する上流タグは [`impacket_0_13_1`](https://github.com/fortra/impacket/tree/impacket_0_13_1) です。以下の行番号はPyPI wheelのソースに対するもので、GitHubのタグと行配置が異なる場合があります。

## 既存機能

| 要件 | 上流の実装 | 本ツールの追加・変更 |
|---|---|---|
| 任意ポート | `examples/smbserver.py` の `-port`、`SimpleSMBServer(listenPort=...)`、`SMBSERVER` のTCPServer基底 | SMBSERVERのTCP待受を再利用。8446を既定、139／445拒否。WindowsではSO_EXCLUSIVEADDRUSEで重複待受を防止 |
| SMB2 | `SMB2Commands.smb2Negotiate`（2837行付近）、`SMBSERVER.processRequest`、`SMB2Support`設定 | ダイアレクト0x0202の提示確認、非対象コマンド・SMB1認証・compound拒否。SMB1形式NegotiateからのSMB2移行を追加 |
| NTLM Type 2 | `SMB2Commands._ntlm_auth`（2968行付近） | Type 1だけを渡し、Type 2生成を再利用。接続ごとにランダムchallengeへ置換 |
| コマンドフック | `hookSmb2Command`（4565行付近） | NEGOTIATEとSESSION_SETUPを差し替え。上流コードの編集なし |
| 認証応答 | 上流はType 3を解析して認証し、応答をJohn形式へ変換する経路を持つ | Type 3を上流認証処理へ渡さず解析し、常に診断上の失敗を返す。明示オプション時のみ上流フォーマッターを再利用してコンソールへ追加表示 |
| ログ | 自由形式ログ、`setLogFile`、John形式出力 | 固定スキーマのJSONL／テキスト。上流自由形式ログを遮断 |
| 接続管理 | 上流ハンドラーは接続登録・NetBIOSフレーム受信・切断管理 | 小さい専用ハンドラーでDirect TCPフレーム、サイズ制限、timeout、理由コード、後片付けを担当 |
| 共有・RPC | SimpleSMBServerはIPC$とSRVS／WKST用RPCを構成 | SMBSERVERを直接構成し、共有や追加RPC待受を作らない |

## `-dropssp` の確認

[公式CLI](https://github.com/fortra/impacket/blob/impacket_0_13_1/examples/smbserver.py) には `-dropssp` があり、既定はFalseです。CLIから `setDropSSP(options.dropssp)` を呼び、global設定 `DropSSP` を経由してサーバーへ反映されます。

[サーバー実装](https://github.com/fortra/impacket/blob/impacket_0_13_1/impacket/smbserver.py) のSMB1 Session Setup（2574行付近）とSMB2の `_ntlm_auth`（3018行付近）のどちらも、DropSSPが有効ならType 2のフラグ全体を `NTLMSSP_DROP_SSP_STATIC` へ置き換えます。

[ntlm.py](https://github.com/fortra/impacket/blob/impacket_0_13_1/impacket/ntlm.py) で定数を確認：

- `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000`
- `NTLMSSP_DROP_SSP_STATIC = 0xe2818215`
- `0xe2818215 & 0x00080000 == 0`

したがってESSは広告されなくなります。ただし「交渉したフラグからESSだけをクリアする」実装ではありません。固定値に他のビットも含まれるため、通常のType 1から組み立てたフラグ集合も置き換わります。「SSP全体の無効化」や「NTLMv2の確実な禁止」を意味すると解釈するのは不正確です。

NTLMの認証バージョンとESSは別の軸です。クライアントが実際に選んだ応答形式、ローカルポリシー、接続中止を観測する必要があります。今回の改修で `--drop-ssp` を追加し、上流と同じ設定経路で固定フラグを選択可能にしました。既定はFalseを維持し、Type 1／2／3を個別に記録します。

## なぜログ設定だけでは足りないか

上流SMB2のType 3成功経路（3144行付近）には `outputToJohnFormat(...)` → `smbServer.log(hash_string)` → 条件付き `writeJohnOutputToFile(...)` があります。`jtr_dump_path` が空でも変換とログ呼出しは残ります。したがって `dump_hashes=False` やログファイル無指定だけに依存せず、Type 3経路そのものを迂回しています。

上流モジュールをmonkey patchしていません。専用クラスの `log` は自由形式出力を破棄し、認証用の資格情報やcallbackを設定せず、Type 3のデータをconnectionDataへ保存しません。処理終了後は接続状態を削除します。

## 形式判定の根拠

[Microsoft MS-NLMP：NTLM v1 Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5) と [NTLMv2_CLIENT_CHALLENGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b) を参照しました。

NTLMv1-ESS候補はLM領域の8バイトclient challenge＋16バイトゼロと24バイトNT応答、ESSの交渉状態を組み合わせて判定します。v2候補は16バイトproofの後ろのblob形式を検査します。proofやresponseの正当性は検証しません。

対象版 `ntlm.computeResponseNTLMv2` はAV終端後の追加4バイトを生成しないため、解析では追加ゼロ領域がある形式とない形式を許容します。AVペアの値は返さず、長さと終端だけを確認します。不正入力が見かけ上の形式に一致する可能性はあり、いずれも推定です。

## 調査対象のSHA-256

PyPI wheelインストール後のファイル：

```text
impacket/smbserver.py
85342874640b35f6ea7182860bff2373b44d56b413aeba0f666133fcc8e9af5d
impacket/ntlm.py
782597e73518466127dfcf3f9e41c8bd27a7d7056fa6e04cfaa4bbfc4d93954b
```

上流コードはこの配布物にコピーしていません。Impacketは上流のライセンスに従う外部依存です。


## 追加レビュー（2026-10-31）

SMB NegotiateとNTLM Type 2は別段階です。SMB2 Negotiate応答はSMBダイアレクトとSPNEGOの利用可能メカニズムを提示します。Type 2はその後のSession Setup内のType 1に対して `_ntlm_auth` が生成します。DropSSPはこのType 2生成の分岐に作用し、SMBダイアレクトの選択を変更しません。

上流 `smb2Negotiate` はnative接続でもSMB1形式bootstrapでも0x0202を返します。0x0210／0x0300／0x0311へ戻り値だけ変更する改修は行っていません。前回版で追加した「クライアントの提示に0x0202がなければ拒否する」検査は維持しつつ、DialectCountの範囲だけを検査して後続context風のデータをダイアレクトと誤認しないようにしました。

SMB1形式bootstrapは `NewSMBPacket`／`SMBCommand` で解析し、SMB2の提示があるNegotiateだけを上流 `SMB2Commands.smb2Negotiate(..., isSMB1=True)` へ渡します。上流 `processRequest` にあるSMB1 fallbackやtraceback出力へ入らない構成です。SMB1 Session Setupは受け付けず、秘密情報が上流認証経路へ流れない境界を維持しています。

SPNEGOについては、先頭メカニズムがNTLMであれば後続メカニズムがある場合も受け付けます。先頭がKerberosのトークンをNTLMへ自動変換する実装ではありません。
