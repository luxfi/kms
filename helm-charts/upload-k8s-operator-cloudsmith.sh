cd secrets-operator
helm dependency update
helm package .
for i in *.tgz; do
    [ -f "$i" ] || break
    cloudsmith push helm --republish kms/helm-charts "$i"
done
cd ..