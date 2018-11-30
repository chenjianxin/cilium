.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

****************************************
Getting Started Using DNS-Based Policies
****************************************

This document serves as an introduction for using Cilium to enforce DNS-based
security policies for Kubernetes pods.

.. include:: gsg_intro.rst
.. include:: minikube_intro.rst
.. include:: cilium_install.rst

Step 2: Deploy the Demo Application
===================================

DNS-based policies are very useful for controlling access to services running outside the Kubernetes cluster. Whether it is cloud services such as S3, DynamoDB, RDS, etc. or it is services in your corporate environment running outside the cluster, DNS provides reliably identity for these external services. CIDR or IP-based policies are cumbersome and hard to maintain as the IPs associated with external services can change frequently. The Cilium DNS-based policies provide an easy mechanism to specify access control while leaving the harder aspects of resolving and enforcing IP-based filters to Cilium. 

In this guide we will learn about:

- Controlling egress access to services outside the cluster using DNS-based policies
- Using patterns (or wildcards) to whitelist a subset of DNS domains
- Combining DNS, port and API-level rules for restricting external service access

Step 3: Create Example App
==========================

The file ``dns-sw-app.yaml`` contains ``deathstar``, an internal cluster service and two pods, ``mediabot`` and ``spaceship``. The ``mediabot`` pod needs access to twitter API services for managing the empire's tweets. However, the ``spaceship`` pods shouldn't have any external service access for obvious reasons. Both the pods should be able to access the internal ``deathstar`` service. 

.. parsed-literal::

    $ kubectl create -f \ |SCM_WEB|\/examples/minikube/dns-sw-app.yaml
    $ kubectl get po,svc
    NAME                             READY   STATUS    RESTARTS   AGE
    pod/deathstar-5fc7c7795d-7ljr8   1/1     Running   0          14s
    pod/deathstar-5fc7c7795d-lvw69   1/1     Running   0          14s
    pod/mediabot                     1/1     Running   0          14s
    pod/spaceship                    1/1     Running   0          14s

    NAME                 TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)   AGE
    service/deathstar    ClusterIP   10.110.127.146   <none>        80/TCP    14s
    service/kubernetes   ClusterIP   10.96.0.1        <none>        443/TCP   16m

Step 4: Check Current Access
============================

Since we have not enforced any policies, both ``mediabot`` and ``spaceship`` have access to twitter API service as well as internal ``deathstar`` service. You can confirm this by running the following commands.

.. parsed-literal::

    $ kubectl exec -it mediabot -- curl -sL https://api.twitter.com
    ...

    $ kubectl exec -it spaceship -- curl -sL https://api.twitter.com
    ...

    $ kubectl exec -it spaceship -- curl -sL deathstar.default.svc.cluster.local/v1
    {
	"name": "Death Star",
        ...
        ...
    }

    $ kubectl exec -it mediabot -- curl -sL deathstar.default.svc.cluster.local/v1
    {   
        ...
        ...
    }

Step 5: Apply DNS Egress Policy
===============================

We will enforce a Cilium network policy which allows:

* Only the ``mediabot`` pods have access to ``api.twitter.com``. 
* Both the pods have access to the internal ``deathstar`` service.

The following Cilium network policy achieves above access controls. 

.. literalinclude:: ../../examples/minikube/dns-policy.yaml

Let's take a closer look at the policy: 

* The first egress section uses ``toFQDNs: matchName`` specification to allow egress to ``api.twitter.com``. The destination DNS should match exactly the name specified in the rule. The ``endpointSelector`` allows only pods with labels ``class: mediabot`` to have the egress access.
* The second egress section allows all pods in the ``default`` namespace to access ``kube-dns`` service. Important to note the part ``rules: dns`` that specifies Cilium to inspect and allow DNS lookups matching specified patterns. In this case, inspect and allow all DNS queries. 
* The third egress section allows all pods in the ``default`` namespace to access the internal ``deathstar`` service. Note that for controlling access to Kubernetes services we use the labels to identify the destination service rather than use DNS. 

Let's apply the policy:

.. parsed-literal::

  $ kubectl create -f \ |SCM_WEB|\/examples/minikube/dns-policy.yaml


Testing the policy, we see that ``mediabot`` has access to ``api.twitter.com`` but doesn't have access to any other external service, for e.g., ``help.twitter.com``. And ``spaceship`` pod doesn't have access to twitter. Both the pods still have access to the internal ``deathstar`` service. 

.. parsed-literal::

    $ kubectl exec -it mediabot -- curl -sL https://api.twitter.com
    ...
    ...

    $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
    ^C 

    $ kubectl exec -it spaceship -- curl -sL https://api.twitter.com
    ^C

    $ kubectl exec -it spaceship -- curl -sL deathstar.default.svc.cluster.local/v1
    {
	"name": "Death Star",
        ...
        ...
    }

    $ kubectl exec -it mediabot -- curl -sL deathstar.default.svc.cluster.local/v1
    {   
        ...
        ...
    }


Step 6: DNS Policies Using Patterns 
===================================

The above policy controlled DNS access based on exact match of the DNS domain name. Often it is required to allow access to a subset of domains. A common example is to control access for cloud services such as AWS S3 which have buckets and regions encoded in the DNS domains. For e.g., the S3 bucket URLs can be of the form, ``<bucketname>.s3.<region>.amazonaws.com``. A pattern based rule such as ``*.s3.*.amazonaws.com`` is needed to allow access to all the S3 buckets irrespective of the region.

Let's use the above example and allow ``mediabot`` pods to access any twitter sub-domain i.e. allow a pattern ``*.twitter.com``. We will achieve this by changing the ``toFQDN`` rule to use ``matchPattern`` instead of ``matchName``.

.. literalinclude:: ../../examples/minikube/dns-pattern.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/minikube/dns-pattern.yaml

Test that ``mediabot`` now has access to multiple twitter services for which the DNS matches the pattern ``*.twitter.com``. Important to note and test that this doesn't allow access to ``twitter.com`` because the ``*.`` in the pattern requires one subdomain to be present in the DNS name. You can simply add more ``matchName`` and ``matchPattern`` clauses to extend the access. 
(`Learn more <http://docs.cilium.io/en/latest/policy/language/?highlight=DNS#dns-based>`_ about specifying DNS rules using patterns and names.)

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -sL https://about.twitter.com
   ... 

   $ kubectl exec -it mediabot -- curl -sL https://twitter.com
   ^C 


Step 7: Combining DNS and Port Rules
====================================

The DNS-based access can be restricted to a specific port by adding an L4 rules section. Continuing with the example, we will restrict access to twitter services to port ``443``. 

.. literalinclude:: ../../examples/minikube/dns-port.yaml

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/minikube/dns-port.yaml

Testing, the access to ``https://help.twitter.com`` will succeed since it access on port 443 but access to ``http://help.twitter.com`` will be blocked since it goes to port 80.

.. parsed-literal:: 
  
   $ kubectl exec -it mediabot -- curl -sL https://help.twitter.com
   ...

   $ kubectl exec -it mediabot -- curl -sL http://help.twitter.com
   ^C  

Step 8: Combining DNS, Port and API-aware Rules
===============================================

DNS and port can be combine with API-aware (L7) rules to further restrict access. This is particularly useful for internal shared service such as Cassandra, Kafka, Memcache, Redis, or HTTP-based services. The below example allows ``spaceship`` pods to access an external service, `starwars.covalent.link` but it restricts the access to a specific port, ``80``, and to a specific action and resource, ``HTTP GET /naboo/landing-request``. 

.. parsed-literal::

  $ kubectl apply -f \ |SCM_WEB|\/examples/minikube/dns-port-l7.yaml

.. parsed-literal::

  $ kubectl exec spaceship -- curl -sL starwars.covalent.link/naboo/landing-request
  Landing request granted.

  ! Welcome to Planet Naboo !

  $ kubectl exec spaceship -- curl -sL starwars.covalent.link/naboo/stats
  Access denied

   
Step 9: Clean-up
================

.. parsed-literal::

   $ kubectl delete -f \ |SCM_WEB|\/examples/minikube/dns-sw-app.yaml
   $ kubectl delete cnp to-fqdn

