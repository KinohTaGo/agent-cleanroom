# agent-cleanroom（日本語）

コーディング用のエージェントを、手元の LLM（Ollama）や API に対して、網を閉じた再現できる環境で
走らせ、実行ごとに検証できる記録を残す道具です。

**状態: 0.1.0（試作版）。** 設計を読めるように早めに公開しています。記録の形は 1.0 までに変わることがあります。
Anthropic とは関係がなく、Anthropic の承認も受けていません。

## なぜ

開発者の機体で走らせたエージェントの CLI は、目に見えない環境を引き継ぎます（全体の指示ファイル・
plugin・hook・記憶・自動で上がった CLI の版・サーバーから取った機能の旗・開いた網）。どれも結果を
変えうるので、2 回の実行を比べることも、後で同じ実行を再現することも難しくなります。

agent-cleanroom はそれを取り除き、残りを固定し、固定できなかった物を記録に書きます。

- **クリーンルーム** — HOME と設定の dir が空・CLI は厳密な版・自己更新と不要な通信は切る・
  root でない利用者で走る。container の中の検査が、何かが持ち込まれていれば実行を止めます。
- **閉じた網** — エージェントの container はどこへも経路を持ちません。gateway が、宣言した
  model の口だけを通します（Ollama なら host の 1 つの port、API なら許した HTTPS の 1 つの先）。
- **固めた container** — `--cap-drop ALL`・`no-new-privileges`・root の file system は読むだけ
  （書けるのは tmpfs と作業の写しだけ）・memory と process の上限。
- **実行の記録** — 実行ごとの dir に、検査の報告・backend の素性（実行系の版・model の名と
  digest・seed を固定したか）・エージェントの出力・作業 dir の差分・`SHA256SUMS`。実行に渡した
  秘密は全部の file から消します。

## はじめ方（同じ機体の Ollama）

要る物: Docker・Python 3.11 以上と [uv](https://docs.astral.sh/uv/)・host の Ollama と
pull 済みの model（agent-cleanroom は model を pull しません）。

```sh
docker build -f images/base/Dockerfile -t agent-cleanroom/base:local .
docker build -f images/claude-code/Dockerfile \
  --build-arg BASE_IMAGE=agent-cleanroom/base:local -t agent-cleanroom/claude-code:local .
uv sync
uv run agent-cleanroom verify --backend ollama --model <model> --workdir ./myproject
uv run agent-cleanroom run --backend ollama --model <model> --workdir ./myproject \
  --prompt "parse() の単体試験を足して" --skip-permissions
uv run agent-cleanroom bundle verify runs/<id>
```

## 範囲

- 固定して記録するのは**環境**です。model の出力を決定的にはしません（そう説明しないこと）。
- 検査は外れを見つける物で、`docker run` の行を握る人に対する守りの境ではありません。
- Mac では model は host（Metal）で走ります。Docker Desktop は GPU を container へ渡せません。
- CI は `linux/amd64` を試します。`linux/arm64`（Apple Silicon）は 0.1 では手元だけで試します。

## まだ／後で

0.2: 多試行と再開・2 つの記録の比べ・`llamacpp` と `litellm`・要求と応答の本文（既定は off）・
seed の固定（実行系が許す所で）・Dependabot と版の遅れの見張り ／ 0.3: Inspect AI と組むかの決め・
arm64 の CI ／ 0.5: 署名・provenance・SBOM・脆弱性の門・registry への公開はここから ／
1.0: 記録の形を固定・再現の手引き・CITATION.cff・最初の安定版。

## 規約

- `claude-code` の image には、Anthropic が npm に出す Claude Code CLI を**改変せず**に入れます
  （© Anthropic PBC）。使い方は Anthropic の規約に従います:
  <https://code.claude.com/docs/en/legal-and-compliance>
- 資格情報は利用者自身の物です。この道具は model への接続を提供せず、利用を代わりに払う・転売する・
  仲介することはなく、資格情報を集める・保存する・転送することもしません（利用者が書いた file を
  container へ渡し、その値を記録から消すだけ）。
- 「Claude Code」は image に入る CLI の名で、この道具の名ではありません。
- MIT の許諾はこの repo の file が対象で、image の中の Claude Code CLI は対象外です。
