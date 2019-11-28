CM_STATUS="$(kubectl get cm -n=xingular | grep access-control-srv-config | wc -l)"

if [ "$CM_STATUS" -eq "1" ]; then
   echo "delete \"access-control-srv-config\" configmap..."
   kubectl delete cm access-control-srv-config -n=xingular
fi

echo "create \"access-control-srv-config\" configmap..."
kubectl create cm access-control-srv-config -n=xingular --from-file=./cfg/
