# Nexo — Ativar Notificações Push

## Passo 1 — Instalar dependência no servidor

No repositório do `server.js`, rode:

```bash
npm install web-push
```

---

## Passo 2 — Gerar as chaves VAPID (só uma vez)

```bash
npx web-push generate-vapid-keys
```

Saída será algo como:
```
Public Key:
BCVxyz...

Private Key:
abc123...
```

Salve as duas chaves — você não vai precisar gerar de novo.

---

## Passo 3 — Configurar no Render.com

No painel do seu serviço no Render:

1. Vá em **Environment** → **Add Environment Variable**
2. Adicione as 3 variáveis:

| Key | Value |
|-----|-------|
| `VAPID_PUBLIC_KEY` | A chave pública gerada no passo 2 |
| `VAPID_PRIVATE_KEY` | A chave privada gerada no passo 2 |
| `VAPID_EMAIL` | `mailto:seu@email.com` (qualquer email seu) |

3. Clique em **Save Changes** — o Render vai redeploiar automaticamente.

---

## Passo 4 — Deploy do index.html

Faça `git push` do `index.html` atualizado para o GitHub Pages normalmente.

---

## Como funciona depois disso

1. Usuário abre o Nexo no Chrome Android (instalado como PWA)
2. Na primeira conexão, o app pede permissão de notificação
3. Se aceitar: o app registra a subscription e envia ao servidor
4. Quando alguém manda mensagem/chamada e o destinatário está offline:
   - O servidor dispara o push pela infraestrutura do Google
   - O Android exibe a notificação mesmo com o app fechado
   - Tocar na notificação abre o Nexo direto na conversa

---

## Ativar/desativar manualmente

O usuário pode ir em **Configurações → Notificações push** para ativar ou desativar a qualquer momento.

---

## Verificar se está funcionando

Acesse `https://nexo-relay2.onrender.com/health` — deve aparecer o campo `push_subs` com o número de usuários inscritos.

---

## Observações de privacidade

- O servidor só sabe **de quem** está vindo a mensagem e **para quem** vai — nunca o conteúdo (criptografado E2E)
- A notificação mostra apenas o nome do remetente + tipo ("enviou uma mensagem")
- Nenhum dado de mensagem trafega pelo Google — só um "ping" dizendo que tem algo novo

