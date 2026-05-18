# AACP Framework Adapters

Drop-in integrations for popular agentic frameworks.
Each adapter: tags input with provenance → runs `detect_segment()` → applies Gateway → wraps or blocks.

## LangChain
```python
from aacp_protocol.adapters.langchain_adapter import AACPChainMiddleware
safe_chain = AACPChainMiddleware(your_chain)
result = safe_chain.run({"input": user_query})
```

## Semantic Kernel
```python
from aacp_protocol.adapters.semantic_kernel_adapter import AACPSKPlugin
plugin = AACPSKPlugin(kernel)
kernel.add_plugin(plugin, plugin_name="AACP")
# Register plugin.before_invoke in SK's pre-invoke pipeline
```

## CrewAI
```python
from aacp_protocol.adapters.crewai_adapter import AACPCrewGuard
guard = AACPCrewGuard()
guard.wrap_crew(your_crew)  # patches crew.kickoff
your_crew.kickoff()
```

## AutoGen
```python
from aacp_protocol.adapters.autogen_adapter import AACPAutoGenFilter
filter = AACPAutoGenFilter()
filter.register(your_agent)  # patches _process_received_message
```

## Design Contract
Every adapter enforces the AACP provenance contract before the LLM sees any text:
1. Tag segment with `source_id`, `source_type`, `trust_tier`, `boundary_crossed`
2. Run `detect_segment()` — returns risk score + verdict + action
3. If `action == reject`: return `[AACP BLOCKED]`
4. If `risk >= 0.35`: wrap content with `BEGIN_UNTRUSTED_CONTEXT`
5. Apply Tool-Sink Gateway before any tool call executes
