# AACP Framework Adapters

Drop-in wrappers for the four most common agentic frameworks.

## LangChain

```python
from aacp_protocol.adapters import AACPLangChainWrapper

protected = AACPLangChainWrapper(your_chain)
try:
    result = protected.invoke({"input": user_input})
except ValueError as e:
    print(f"Blocked: {e}")
```

## Semantic Kernel

```python
from aacp_protocol.adapters import AACPSemanticKernelHook

hook = AACPSemanticKernelHook()
kernel.add_filter('function_invocation', hook.before_invoke)
```

## CrewAI

```python
from aacp_protocol.adapters import AACPCrewAIAdapter

protected = AACPCrewAIAdapter(your_crew)
protected.kickoff(inputs={"topic": user_input})
```

## AutoGen

```python
from aacp_protocol.adapters import AACPAutoGenAdapter

protected_agent = AACPAutoGenAdapter(your_agent)
# Messages to your_agent are now screened automatically
```

## Trust Levels

All adapters accept a `trust_level` parameter:

```python
from aacp_protocol import TrustLevel

# Strictest screening
wrapper = AACPLangChainWrapper(chain, trust_level=TrustLevel.UNTRUSTED)

# Relax for known-good external sources
wrapper = AACPLangChainWrapper(chain, trust_level=TrustLevel.EXTERNAL)
```
