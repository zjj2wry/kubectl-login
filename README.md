# kubectl-login

kubectl-login 用于登陆 kubernetes 集群，需要 [kubernetes api-server 开启 oidc authn](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)。

## example

> 可以直接使用命令登陆集群，如果使用最新版本的 kubectl(1.13)，可以把 kubectl-login 移动到 /usr/local/bin/ 目录下，然后使用 kubectl login 登陆集群。

### 配置 kubeconfig 的集群和 contexts 信息
```text
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {ca}
    server: https://192.168.21.133:6443
  name: cps-console-web
contexts:
- context:
    cluster: cps-console-web
    user: kubectl
  name: default
current-context: default
kind: Config
preferences: {}
```

### 配置 kubeconfig users 信息
如上，现在只有被访问集群的目标地址和 context 信息，但是缺少访问集群的 credentials 信息，配置 oidc auth provider 的配置。

```bash
kubectl config set-credentials USER_NAME \
   --auth-provider=oidc \
   --auth-provider-arg=idp-issuer-url=( issuer url ) \
   --auth-provider-arg=client-id=( your client id ) \
   --auth-provider-arg=client-secret=( your client secret ) \
```

### 执行 kubectl login 命令获取 oidc IDToken 和 refresh token

执行后如果之前没有登陆过，会先跳到认证中心的登陆页，如果之前登陆过则会保存返回的 IDToken 和 refresh token 到 kubeconfig 文件。使用 kubectl config view 查看当前的 auth 信息。另外获取的 id-token 可以直接用于访问 hodor API。
```
➜ kubectl config view
users:
- name: kubectl
  user:
    auth-provider:
      config:
        client-id: kubernetes
        client-secret: kubernetes
        id-token: {very long token}
        idp-issuer-url: http://192.168.10.168:8010
        refresh-token: 9qHcywA36HTAwKzbjHJbLw8t_qD
      name: oidc
```

## future work
1. support logout
2. support https
