# pocket-ssh-agent

SSH の秘密鍵をスマホに置き、PC で `git push` や `ssh` をするたびに**スマホで承認**する SSH エージェントです。
PC には鍵が存在しないので、PC からパスフレーズや鍵ファイルを盗まれても使えません。

```
PC                                                   スマホ
ssh / git ──▶ pocket-ssh-agent ◀──https (Tailscale)── PWA（静的サイト）
              ・名前付きパイプ / Unix ソケット            ・Ed25519 鍵（取り出し不可の WebCrypto 鍵）
              ・署名要求をスマホへ中継                    ・内容を自分で解析して表示
              ・返ってきた署名を検証                      ・承認したときだけ署名
```

- PC 側は Go 製の単体バイナリ（Windows / macOS / Linux）。
- スマホ側はインストール不要の PWA。`web/` を静的サイトとして配信して使います（配信先は自分で用意します。[PWA の配信先](#pwa-の配信先)を参照）。
- 通信は Tailscale の tailnet 内だけで完結し、中継サーバーはありません。
- 鍵は普通の `ssh-ed25519` なので、GitHub を含むどの SSH サーバーでも使えます。

> **状態: 実験的な初期版です。** 実機（Windows + iPhone）での検証はこれからです。

## 守れるもの・守れないもの

| | |
|---|---|
| ✅ PC のマルウェアに鍵を盗まれる | 鍵はスマホの中だけ。PC には公開鍵しかありません |
| ✅ 知らないうちに鍵を使われる | 署名のたびにスマホでの承認が必要です |
| ✅ 汎用の署名器として悪用される | スマホは「SSH ログイン」と「SSHSIG（git 署名など）」以外の形式には署名しません |
| ✅ PC の他ユーザーや tailnet 上の他端末からの割り込み | ペアリング後は共有鍵による HMAC で双方向に認証します。tsnet モードではローカルのポート自体を開きません。serve モードで agent の停止中にポートを乗っ取られても、要求を偽造したり認証情報を盗んだりできません |
| ⚠️ 承認のタイミングに紛れ込まれる | 侵害された PC は、あなたが push した瞬間に別の要求を送れます。件数や接続先の表示、カードが出てから 1 秒間は承認できない仕組みで気づけるようにしていますが、完全には防げません（YubiKey などでも同じです） |
| ⚠️ PC の前にいないときの要求 | YubiKey（タッチ）やスマホのパスキー（Bluetooth で近接を確認）と違い、Tailscale 経由なのでどこからでも承認できてしまいます。侵害された PC が、あなたが外出中などに要求を出すこともできます。**自分で操作した直後以外の要求は拒否してください** |
| ⚠️ 偽のペアリングリンク | 他人の PC とペアリングさせられると、その PC から署名を要求されます。確認画面に接続先と PC 名を表示し、Tailscale（`*.ts.net`）以外や、現在のペアリングと別の tailnet の場合は警告します（初めてのペアリングでは比較対象がないため後者の警告は出ません）。スマホの鍵はペアリングし直しても同じなので、ペアリング後も**要求を承認しない限り**署名はされません。自分の PC に表示した QR コード以外ではペアリングしないでください |
| ⚠️ `ssh -A` の転送先からの要求 | 転送された agent 経由の要求には警告を表示します |
| ⚠️ 接続先の表示 | 「署名で確認済み」は署名データに含まれるホスト鍵なので信頼できます。「PC の申告」は PC が自己申告したもので、侵害された PC は偽れます |
| ❌ スマホ自体の侵害 | スマホやブラウザが乗っ取られた場合は守れません |

## PWA の配信先

PWA（`web/`）は、次の条件を満たす場所に静的サイトとして配信してください。

- **HTTPS で配信する**（WebCrypto とカメラの利用に必要）
- **PC から配信しない**: PC から配信すると、侵害された PC が「承認画面なしで署名する偽の PWA」を配信できてしまいます
- **オリジンを他のサイトと共有しない**: 鍵は「取り出せない」設定ですが、同じオリジンで動く JavaScript からは承認なしで署名に使えてしまいます。
  GitHub Pages では、同じアカウントのすべての Pages サイトが同じオリジン（`https://<アカウント>.github.io`）になる点に注意してください

配信先の例:

| 配信先 | 条件 |
|---|---|
| 独自ドメイン（サブドメイン可）+ GitHub Pages などの静的ホスティング | 最も確実。そのサブドメインでは他のサイトを公開しない |
| PWA 専用の GitHub アカウントの Pages | そのアカウントでは他の Pages サイトを公開しない |

**配信先は最初に決めてから使い始めてください。** スマホの鍵やペアリングは配信先のオリジンに保存されるので、後から変えると鍵の作り直しと GitHub などへの再登録が必要になります。

### このリポジトリの GitHub Actions で GitHub Pages に配信する場合

`.github/workflows/pages.yml` で `web/` を GitHub Pages に配信できます。共有オリジンに誤って公開しないよう、**既定では無効**です。

1. Settings → Pages → Source を「GitHub Actions」にする
2. Settings → Secrets and variables → Actions → Variables に `DEPLOY_PAGES` = `true` を追加する
3. （独自ドメインの場合）Settings → Pages → Custom domain を設定し、「Enforce HTTPS」を有効にする。ドメインはアカウント設定で検証済み（verified）にしておく

### PWA の URL を agent に教える

agent は、ペアリング用 QR のリンク先と、受け付けるブラウザのオリジンに PWA の URL を使います。

- 初回に `-web-url https://<PWA の URL>/` を付けて起動します。設定ファイルに保存されるので、2 回目以降は不要です
- リポジトリ変数 `PWA_URL` を設定しておくと、Releases のバイナリに既定値として埋め込まれます（Docker なら `--build-arg PWA_URL=...`）

## 必要なもの

- [Tailscale](https://tailscale.com/) のアカウント（tailnet）
  - スマホには Tailscale アプリを入れて tailnet に参加してください
  - **PC には Tailscale を入れなくて構いません。** agent が自分で tailnet に参加します（後述の `serve` モードを使う場合を除く）
  - 管理画面の DNS 設定で **MagicDNS** と **HTTPS Certificates** を有効にしてください
- スマホ: iOS 17 以降の Safari、または最近の Chrome（WebCrypto の Ed25519 が必要）

## セットアップ

### 1. PC で agent を起動

[Releases](https://github.com/tksugimoto/pocket-ssh-agent/releases) から OS に合ったバイナリをダウンロードします（Go 1.27 以降がある場合は `go install github.com/tksugimoto/pocket-ssh-agent/cmd/pocket-ssh-agent@latest`、Docker なら後述の「開発」の方法でも可）。
Releases のバイナリにはビルドの来歴証明が付いているので、`gh attestation verify <ファイル> --repo tksugimoto/pocket-ssh-agent` でこのリポジトリの GitHub Actions がビルドしたものか確認できます。

```powershell
pocket-ssh-agent -web-url https://<PWA の URL>/   # -web-url は初回のみ
```

agent は Tailscale のライブラリ（[tsnet](https://tailscale.com/kb/1244/tsnet)）で、自分自身を tailnet の 1 台（既定の名前は `pocket-ssh-<PC 名>`）として参加させます。

- **初回だけ**、ログに表示される `https://login.tailscale.com/...` をブラウザで開いて承認します。以降は保存された状態で自動的に接続します。
  ブラウザを使わずに済ませたい場合は、管理画面で発行した認証キーを環境変数 `TS_AUTHKEY` に入れて起動します。
- スマホからは `https://pocket-ssh-<PC 名>.<tailnet 名>.ts.net` で、正規の HTTPS 証明書を使って接続します。PC のポートは開きません。
- 続けてペアリング用の QR コードが表示されます。

> 管理画面の「Machines」で、この端末の **Key expiry を無効**にしておくと、180 日ごとの再ログインが不要になります。

#### `serve` モード（PC に Tailscale を入れている場合の代替）

```powershell
pocket-ssh-agent -mode serve
tailscale serve --bg --https=7766 http://127.0.0.1:7766   # 初回だけ
```

agent は `127.0.0.1:7766` でだけ待ち受け、PC の Tailscale が `tailscale serve` で tailnet に公開します。

### 2. スマホでペアリング

1. スマホで PWA の URL を開きます。
2. **iPhone の場合は先に「ホーム画面に追加」して、追加したアプリから開いてください。** Safari とホーム画面のアプリは保存領域が別で、Safari の保存データはしばらく使わないと消えることがあります。
3. アプリの「QR コードを読み取る」で、PC に表示された QR を読み取ります。
   （カメラアプリで読み取ると Safari で開いてしまうため、アプリ内で読み取ってください。Android はどちらでも可）
4. 「ペアリングする」を押すと鍵が作られ、公開鍵が表示されます。

QR コードの有効期限（既定 10 分）が切れたときやペアリングに失敗したときは、agent を `-pair` 付きで起動し直すと新しい QR が表示されます。
スマホがすでにペアリング済みのときは、リンクからのペアリングは受け付けません（他のサイトのリンクでペアリングを差し替えられないようにするため）。ペアリングし直すには、PWA の「設定」→「ペアリングを解除」をしてから、アプリ内で QR コードを読み取ってください。

### 3. 公開鍵を登録

表示された公開鍵（PC でも `pocket-ssh-agent pubkey` で表示可）を、GitHub の **Settings → SSH and GPG keys** や、接続先サーバーの `authorized_keys` に登録します。

### 4. SSH クライアントから使う

agent を起動したまま、SSH クライアントに agent の場所を教えます。

**Windows（OpenSSH）**

```powershell
$env:SSH_AUTH_SOCK = '\\.\pipe\pocket-ssh-agent'
ssh -T git@github.com
```

Git for Windows 同梱の ssh は名前付きパイプの agent を使えないので、Windows の OpenSSH を使うよう設定します。

```powershell
git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
```

**macOS / Linux**

```sh
export SSH_AUTH_SOCK="$HOME/.pocket-ssh-agent/agent.sock"   # 起動時のログに表示されるパス
ssh -T git@github.com
```

スマホで PWA を開いておくと承認画面が出ます。承認すると接続が進みます。

### devcontainer で使う（未検証）

VS Code の Dev Containers は、Windows 標準の ssh-agent（`\\.\pipe\openssh-ssh-agent`）をコンテナへ転送します。
Windows の ssh-agent サービスを止めて、pocket-ssh-agent をその名前で起動すると、コンテナ内からも使える見込みです。

```powershell
Stop-Service ssh-agent
Set-Service ssh-agent -StartupType Disabled
pocket-ssh-agent -socket '\\.\pipe\openssh-ssh-agent'
```

### git のコミット署名にも使う（任意）

```sh
git config --global gpg.format ssh
git config --global user.signingkey "key::$(pocket-ssh-agent pubkey)"
git config --global commit.gpgsign true
```

## オプション

```
pocket-ssh-agent [flags]
  -mode        tsnet（既定。agent が自分で tailnet に参加）または serve
  -ts-hostname tsnet: tailnet 上の名前（既定: pocket-ssh-<PC 名>）
  -ts-dir      tsnet: 状態の保存先（既定: ユーザー設定フォルダ）
  -listen      serve: スマホ用 API の待ち受け（既定: 127.0.0.1:7766、ループバックのみ）
  -socket      agent のソケット（Windows は名前付きパイプ）
  -public-url  スマホから見た URL（既定: Tailscale から自動判定）
  -web-url     PWA の URL（初回に指定。設定ファイルに保存される。変えると再ペアリングが必要）
  -name        スマホに表示する PC 名（既定: ホスト名）
  -timeout     承認を待つ時間（既定: 90s）
  -pair        ペアリングし直す（スマホを替えたときなど）
pocket-ssh-agent pubkey        ペアリング済みの公開鍵を表示
```

## PC を再起動したら

agent を起動し直すだけです。ペアリング（共有鍵・スマホの公開鍵）は設定ファイルに、tailnet への参加状態は `-ts-dir` に保存されているので、ペアリングも鍵の作成もやり直す必要はありません。
ログオン時に自動で起動したい場合は、Windows ならタスク スケジューラ、macOS なら launchd、Linux なら systemd のユーザーサービスに登録してください。

保存場所（Windows の例）:
- 設定: `%AppData%\pocket-ssh-agent\config.json`
- tailnet の状態: `%AppData%\pocket-ssh-agent\tsnet\`（この端末の Tailscale の鍵を含むので、他人に渡さないでください）

## 制限事項

- 承認するには、スマホで PWA を**開いたまま**にしておく必要があります（通知は今後対応予定）。
- PWA のデータ（鍵）を消すと鍵は復元できません。新しい鍵を作って登録し直してください。
- ペアリングできるスマホは PC 1 台につき 1 台です。
- tsnet モードでは、Tailscale の通常のクライアントと同様に診断ログが Tailscale に送られます。止める場合は環境変数 `TS_NO_LOGS_NO_SUPPORT=true` を設定してください（Tailscale のサポートは受けられなくなります）。
- スマホと PC の時計が 2 分以上ずれていると接続できません（認証にタイムスタンプを使うため）。
- Android の Chrome では、初回に「ローカル ネットワークへのアクセス」の許可を求められることがあります。許可しないと PC に接続できません。

## 今後

- Web Push による承認通知（PC から直接送信。中継サーバーは不要）
- 承認時の生体認証（WebAuthn）と、パスキー PRF による鍵の暗号化
- 要求元プロセス名の表示
- 番号の照合（PC のターミナルに出た番号をスマホで選ばないと承認できない）や、PC を操作していないときの要求の自動拒否
- ペアリングごとに鍵を作り直す（偽のペアリングリンクで他人の PC とペアリングしても、登録済みの鍵を使われないようにする。代わりにペアリングし直すたびに公開鍵の登録が必要になる）

## 通信の仕組み

1. **ペアリング**: PC が QR に「接続先 URL」と「使い捨てコード（128 bit）」を載せます。スマホは鍵を（まだなければ）作り、公開鍵とコードを送ります。PC は 32 バイトの共有鍵を返し、コードで作った HMAC を添えて「QR を表示した本物の PC からの応答」であることを証明します。
2. **以降の通信**: 共有鍵そのものは二度と送りません。
   - スマホ → PC: リクエストごとに、メソッド・パス・時刻・ノンス・本文のハッシュに対する HMAC を付けます（再送は拒否）。
   - PC → スマホ: 署名要求ごとに HMAC を付け、スマホは検証できない要求を無視します。
3. **署名**: スマホは要求データを自分で解析し、許可した形式だけを、ユーザーが承認したときに署名します。PC は返ってきた署名を公開鍵で検証してから SSH クライアントに返します。

スマホ側では共有鍵を取り出し不可の HMAC 鍵として、SSH 鍵を取り出し不可の Ed25519 鍵として IndexedDB に保存します。

## 開発

### Docker でビルド・テスト（Go や Node.js のインストール不要）

```sh
docker build --target dist --output dist .   # 全 OS 向けのバイナリを ./dist に出力
                                             # （--build-arg PWA_URL=https://... で PWA の URL を埋め込み可）
docker build --target test .                 # go vet / go test / PWA のテスト
```

Windows なら `dist\pocket-ssh-agent-windows-amd64.exe` をホストで実行します（agent は名前付きパイプを使うので、コンテナ内ではなくホストで動かします）。

### ローカルにツールがある場合

```sh
go test -race ./...        # Go のテスト
npm ci && npm test         # PWA ライブラリのテスト（Node 22+）
bash scripts/e2e.sh        # agent + 擬似スマホ + OpenSSH（ssh / sshd が必要）
npx playwright install chromium && node test/e2e/ui.mjs   # 実際の PWA を Chromium で操作
```

- PC 側: `cmd/pocket-ssh-agent`, `internal/`
- スマホ側: `web/`（ビルド不要の素の ES モジュール）。QR 読み取りに [jsQR](https://github.com/cozmo/jsQR) 1.4.0（Apache-2.0）を `web/vendor/jsqr/` に同梱しています。
- アイコン: `python3 scripts/gen-icons.py`

## ライセンス

MIT
