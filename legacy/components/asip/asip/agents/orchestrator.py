from typing import TypedDict, Dict, Any, List, Optional
from langgraph.graph import StateGraph, END

# Import agents
from .triage_agent import TriageAgent
from .rca_agent import RCAAgent
from .qa_agent import QAAgent
from .report_agent import ReportAgent

class GraphState(TypedDict):
    investigation_id: str
    alert_title: str
    alert_details: str
    triage_data: Dict[str, Any]
    graph_data: Dict[str, Any]
    logs: List[Dict[str, Any]]
    rca_data: Dict[str, Any]
    qa_data: Dict[str, Any]
    final_report: str
    qa_iterations: int

# Initialize agents
triage_agent = TriageAgent()
rca_agent = RCAAgent()
qa_agent = QAAgent()
report_agent = ReportAgent()

async def triage_node(state: GraphState) -> Dict[str, Any]:
    """Triage node classifying the initial alert."""
    triage_res = await triage_agent.execute(
        alert_title=state["alert_title"],
        alert_details=state["alert_details"]
    )
    return {"triage_data": triage_res}

async def rca_node(state: GraphState) -> Dict[str, Any]:
    """Correlation and Root Cause Analysis node."""
    # Lookup similar incidents from semantic memory
    similar_incidents = []
    try:
        from ..rag.incident_memory import IncidentMemoryManager
        mem_mgr = IncidentMemoryManager()
        similar_incidents = await mem_mgr.search_similar_incidents(state["alert_title"], limit=2)
    except Exception:
        pass

    # Lookup standard playbooks
    playbooks = []
    try:
        from ..rag.playbook_rag import PlaybookRAGManager
        playbook_mgr = PlaybookRAGManager()
        playbooks = await playbook_mgr.get_recommended_playbooks(state["alert_title"])
    except Exception:
        pass

    # If QA returned issues, append them to input so RCA can address them
    qa_feedback = ""
    if state.get("qa_data") and state["qa_data"].get("issues"):
        qa_feedback = f"\nValidation Check Feedback from QA Agent (Please correct these details): {state['qa_data']['issues']}"

    triage_inputs = state["triage_data"]
    if qa_feedback:
        triage_inputs = triage_inputs.copy()
        triage_inputs["initial_hypothesis"] += qa_feedback

    rca_res = await rca_agent.execute(
        triage_data=triage_inputs,
        graph_data=state["graph_data"],
        sample_logs=state["logs"],
        similar_incidents=similar_incidents,
        recommended_playbooks=playbooks
    )
    return {"rca_data": rca_res}

async def qa_node(state: GraphState) -> Dict[str, Any]:
    """Adversarial QA validation checking logs citation."""
    qa_res = await qa_agent.execute(
        rca_data=state["rca_data"],
        sample_logs=state["logs"]
    )
    current_iterations = state.get("qa_iterations", 0)
    return {
        "qa_data": qa_res,
        "qa_iterations": current_iterations + 1
    }

async def report_node(state: GraphState) -> Dict[str, Any]:
    """Compiles the final incident playbook and report."""
    report_res = await report_agent.execute(
        triage_data=state["triage_data"],
        rca_data=state["rca_data"],
        qa_data=state["qa_data"]
    )
    return {"final_report": report_res}

def route_after_qa(state: GraphState) -> str:
    """Routes to reporting if QA approved, else loops back to RCA to correct claims."""
    qa = state.get("qa_data", {})
    iterations = state.get("qa_iterations", 0)
    
    if qa.get("is_valid") or iterations >= 3:
        return "generate_report"
    return "rebuild_rca"

# Construct State Graph
workflow = StateGraph(GraphState)

# Add nodes
workflow.add_node("triage", triage_node)
workflow.add_node("rca", rca_node)
workflow.add_node("qa", qa_node)
workflow.add_node("report", report_node)

# Set entry point
workflow.set_entry_point("triage")

# Connect static edges
workflow.add_edge("triage", "rca")
workflow.add_edge("rca", "qa")

# Connect conditional validation loopback
workflow.add_conditional_edges(
    "qa",
    route_after_qa,
    {
        "generate_report": "report",
        "rebuild_rca": "rca"
    }
)

# Terminate edge
workflow.add_edge("report", END)

# Compile
investigation_graph = workflow.compile()
