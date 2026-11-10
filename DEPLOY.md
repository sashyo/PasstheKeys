# Deploy to Azure Container Apps

Runs the whole demo as **one Container App with two containers**:

- `app` (this repo's `server.mjs`) holds the public HTTPS ingress and reverse-proxies
  `/api/*` to Pocket ID over `localhost`.
- `pocket-id` is a sidecar listening on `1411`, with its data on an Azure Files share so
  users and passkeys survive restarts.

Both containers in one app share `localhost`, so the app reaches Pocket ID at
`127.0.0.1:1411`. WebAuthn needs one stable HTTPS origin, which the Container App ingress
provides.

> This is a live passkey-harvesting relay. Deploy it as a controlled demo with disposable
> test users, and delete it when you are done.

## Prerequisites

- Azure CLI (`az`) logged in: `az login`
- The container-apps extension: `az extension add --name containerapp --upgrade`
- An Azure subscription where you can create a resource group, ACR, and Container Apps

## 1. Names and resource group

```bash
RG=passthekeys-rg
LOC=australiaeast                 # any region with Container Apps
ACR=passthekeys$RANDOM            # must be globally unique, lowercase
ENV=passthekeys-env
APP=passthekeys                   # becomes part of the public hostname
STORAGE=passthekeys$RANDOM        # storage account, globally unique, lowercase

az group create -n $RG -l $LOC
```

## 2. Build and push the app image (no local Docker needed)

```bash
az acr create -n $ACR -g $RG --sku Basic --admin-enabled true
# build from the pocketid-demo folder (which holds the Dockerfile)
az acr build --registry $ACR --image passthekeys-app:latest ./pocketid-demo
```

## 3. Container Apps environment

```bash
az containerapp env create -n $ENV -g $RG -l $LOC
```

## 4. Azure Files share for Pocket ID data (persistence)

```bash
az storage account create -n $STORAGE -g $RG -l $LOC --sku Standard_LRS
KEY=$(az storage account keys list -n $STORAGE -g $RG --query "[0].value" -o tsv)
az storage share create --account-name $STORAGE --account-key "$KEY" -n pid-data

az containerapp env storage set -g $RG -n $ENV \
  --storage-name pid-data \
  --azure-file-account-name $STORAGE \
  --azure-file-account-key "$KEY" \
  --azure-file-share-name pid-data \
  --access-mode ReadWrite
```

## 5. Compute the public URL and secrets

The ingress hostname is `<APP>.<env default domain>`, known before you deploy, so you can
set `APP_URL` up front (WebAuthn binds to it).

```bash
ENV_DOMAIN=$(az containerapp env show -n $ENV -g $RG --query properties.defaultDomain -o tsv)
APP_URL=https://$APP.$ENV_DOMAIN
ENCRYPTION_KEY=$(openssl rand -base64 24)
STATIC_API_KEY=$(openssl rand -hex 24)
ACR_SERVER=$(az acr show -n $ACR -g $RG --query loginServer -o tsv)
ACR_PASS=$(az acr credential show -n $ACR --query "passwords[0].value" -o tsv)
echo "APP_URL=$APP_URL"
```

## 6. Deploy the Container App

Write the app definition (two containers, one ingress, the Azure Files volume), then
create it. Keep it to a single replica: the attacker sessions and per-victim challenges
live in the app's memory, so multiple replicas would split that state.

```bash
cat > app.yaml <<YAML
properties:
  managedEnvironmentId: $(az containerapp env show -n $ENV -g $RG --query id -o tsv)
  configuration:
    activeRevisionsMode: Single
    ingress:
      external: true
      targetPort: 8080
      transport: auto
    registries:
      - server: $ACR_SERVER
        username: $ACR
        passwordSecretRef: acr-pass
    secrets:
      - name: acr-pass
        value: "$ACR_PASS"
      - name: encryption-key
        value: "$ENCRYPTION_KEY"
      - name: static-api-key
        value: "$STATIC_API_KEY"
  template:
    scale:
      minReplicas: 1
      maxReplicas: 1
    volumes:
      - name: pid-data
        storageType: AzureFile
        storageName: pid-data
    containers:
      - name: app
        image: $ACR_SERVER/passthekeys-app:latest
        resources: { cpu: 0.25, memory: 0.5Gi }
        env:
          - name: PORT
            value: "8080"
          - name: PID_PORT
            value: "1411"
          - name: STATIC_API_KEY
            secretRef: static-api-key
      - name: pocket-id
        image: ghcr.io/pocket-id/pocket-id:latest
        resources: { cpu: 0.5, memory: 1.0Gi }
        volumeMounts:
          - volumeName: pid-data
            mountPath: /app/data
        env:
          - name: PORT
            value: "1411"
          - name: APP_URL
            value: "$APP_URL"
          - name: TRUST_PROXY
            value: "true"
          - name: ENCRYPTION_KEY
            secretRef: encryption-key
          - name: STATIC_API_KEY
            secretRef: static-api-key
YAML

az containerapp create -n $APP -g $RG --yaml app.yaml
```

## 7. Use it

```bash
echo "Login:    $APP_URL/login"
echo "Attacker: $APP_URL/attacker"
```

Open `/login`, create an account with a passkey (open sign-up is on because
`STATIC_API_KEY` is set), then sign in. Watch the row appear on `/attacker`.

## Notes

- **Single replica.** Captured sessions and pending challenges are in-memory, so keep
  `minReplicas: maxReplicas: 1`. Restarting the app clears captured sessions; Pocket ID
  users and passkeys persist on the Azure Files share.
- **Reset Pocket ID.** Delete the share's contents (or recreate the share) to wipe users.
- **Custom domain.** To use your own hostname, add it to the Container App, then set
  `APP_URL` to that host and update the app. Passkeys are bound to whatever `APP_URL` is,
  so changing it invalidates existing passkeys.
- **Alternative (ACI).** Azure Container Instances can run the same two containers in a
  group sharing `localhost`, but you must add your own TLS (a hostname with a cert), since
  ACI has no managed HTTPS ingress. Container Apps is simpler for this reason.

## Teardown

```bash
az group delete -n $RG --yes --no-wait
```
