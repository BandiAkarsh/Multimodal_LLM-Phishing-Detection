"""
Chat API for Phishing Detection Explainability

Provides REST endpoints for:
- Explaining detection results
- Follow-up questions
- Chat history management
"""

import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import auth dependencies
try:
    from auth import get_current_user
    auth_available = True
except ImportError:
    auth_available = False
    def get_current_user():
        return {"user_id": "anonymous"}


# ============== Request/Response Models ==============

class ExplainRequest(BaseModel):
    """Request model for explaining a detection result."""
    url: str = Field(..., description="URL to explain")
    classification: str = Field(..., description="Classification result")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    features: Dict[str, Any] = Field(default_factory=dict, description="URL features")
    ml_prediction: Optional[Dict] = Field(None, description="ML model prediction")
    llm_analysis: Optional[Dict] = Field(None, description="LLM analysis")
    toolkit_detection: Optional[Dict] = Field(None, description="Toolkit detection")
    typosquatting: Optional[Dict] = Field(None, description="Typosquatting detection")
    use_llm: bool = Field(True, description="Use LLM for explanation (slower but better)")


class ExplainResponse(BaseModel):
    """Response model for explanation."""
    explanation_id: str = Field(..., description="Unique explanation ID")
    url: str
    classification: str
    confidence: float
    explanation: str
    key_factors: List[Dict[str, Any]]
    recommendations: List[str]
    technical_details: Dict[str, Any]
    created_at: str


class FollowUpRequest(BaseModel):
    """Request model for follow-up questions."""
    explanation_id: str = Field(..., description="ID of previous explanation")
    question: str = Field(..., description="Follow-up question")


class FollowUpResponse(BaseModel):
    """Response model for follow-up answers."""
    explanation_id: str
    question: str
    answer: str
    created_at: str


class ChatMessage(BaseModel):
    """Chat message model."""
    role: str = Field(..., description="Message role (user/assistant)")
    content: str = Field(..., description="Message content")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ChatSessionResponse(BaseModel):
    """Response model for chat session."""
    session_id: str
    messages: List[ChatMessage]
    created_at: str
    updated_at: str


# ============== Chat Session Manager ==============

class ChatSessionManager:
    """Manages chat sessions and history."""
    
    def __init__(self):
        self.sessions: Dict[str, Dict] = {}
    
    def create_session(self) -> str:
        """Create a new chat session."""
        session_id = str(uuid4())
        self.sessions[session_id] = {
            "messages": [],
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }
        return session_id
    
    def add_message(self, session_id: str, role: str, content: str) -> None:
        """Add a message to a session."""
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        self.sessions[session_id]["messages"].append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.sessions[session_id]["updated_at"] = datetime.utcnow().isoformat()
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a chat session."""
        return self.sessions.get(session_id)
    
    def get_all_sessions(self) -> List[Dict]:
        """Get all chat sessions."""
        return [
            {
                "session_id": sid,
                "message_count": len(sess["messages"]),
                "created_at": sess["created_at"],
                "updated_at": sess["updated_at"],
            }
            for sid, sess in self.sessions.items()
        ]


# ============== Initialize Components ==============

# Chat session manager
chat_manager = ChatSessionManager()

# Explainability engine (lazy loaded)
_explainer = None


def get_explainer(use_llm: bool = True):
    """Get or create explainability engine."""
    global _explainer
    
    if use_llm:
        if _explainer is None:
            from explainability import ExplainabilityEngine
            print("Initializing LLM-based explainability engine...")
            _explainer = ExplainabilityEngine()
        return _explainer
    else:
        from explainability import LightweightExplainer
        return LightweightExplainer()


# ============== API Router ==============

router = APIRouter(prefix="/api/v1/chat", tags=["Chat & Explainability"])


@router.post("/explain", response_model=ExplainResponse)
async def explain_detection(
    request: ExplainRequest,
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Explain a detection result in human-readable format.
    
    Provides:
    - Clear explanation of why the URL was classified
    - Key factors that influenced the decision
    - Actionable recommendations
    """
    try:
        # Get explainer
        explainer = get_explainer(use_llm=request.use_llm)
        
        # Generate explanation
        result = explainer.explain_detection(
            url=request.url,
            classification=request.classification,
            confidence=request.confidence,
            features=request.features,
            ml_prediction=request.ml_prediction,
            llm_analysis=request.llm_analysis,
            toolkit_detection=request.toolkit_detection,
            typosquatting=request.typosquatting,
        )
        
        # Add explanation ID
        explanation_id = str(uuid4())
        result["explanation_id"] = explanation_id
        result["created_at"] = datetime.utcnow().isoformat()
        
        # Create chat session and store
        session_id = chat_manager.create_session()
        
        # Add user query
        chat_manager.add_message(
            session_id, "user",
            f"Why was {request.url} classified as {request.classification}?"
        )
        
        # Add assistant response
        chat_manager.add_message(
            session_id, "assistant",
            result["explanation"]
        )
        
        result["session_id"] = session_id
        
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating explanation: {str(e)}"
        )


@router.post("/followup", response_model=FollowUpResponse)
async def followup_question(
    request: FollowUpRequest,
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Ask a follow-up question about a previous explanation.
    """
    try:
        # Get session
        session = chat_manager.get_session(request.explanation_id)
        
        if not session:
            # Try explanation_id as session_id
            session = chat_manager.get_session(request.explanation_id)
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Explanation session not found"
            )
        
        # Get explainer (use LLM for follow-ups)
        explainer = get_explainer(use_llm=True)
        
        # Build previous context from messages
        previous_context = {
            "url": "previous URL",  # Would need to store this properly
            "classification": "previous classification",
            "confidence": 0.0,
            "key_factors": [],
        }
        
        # Find the assistant message with explanation
        for msg in reversed(session["messages"]):
            if msg["role"] == "assistant":
                # Extract key info from previous explanation
                # For now, use a simple approach
                break
        
        # Generate answer
        answer = explainer.answer_followup(
            question=request.question,
            previous_context=previous_context
        )
        
        # Add to chat history
        chat_manager.add_message(request.explanation_id, "user", request.question)
        chat_manager.add_message(request.explanation_id, "assistant", answer)
        
        return FollowUpResponse(
            explanation_id=request.explanation_id,
            question=request.question,
            answer=answer,
            created_at=datetime.utcnow().isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error answering follow-up: {str(e)}"
        )


@router.get("/history", response_model=List[Dict])
async def get_chat_history(
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get all chat sessions.
    """
    return chat_manager.get_all_sessions()


@router.get("/session/{session_id}", response_model=ChatSessionResponse)
async def get_session(
    session_id: str,
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Get a specific chat session.
    """
    session = chat_manager.get_session(session_id)
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return ChatSessionResponse(
        session_id=session_id,
        messages=[ChatMessage(**msg) for msg in session["messages"]],
        created_at=session["created_at"],
        updated_at=session["updated_at"],
    )


@router.delete("/session/{session_id}")
async def delete_session(
    session_id: str,
    current_user: Dict = Depends(get_current_user) if auth_available else None
):
    """
    Delete a chat session.
    """
    if session_id not in chat_manager.sessions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    del chat_manager.sessions[session_id]
    
    return {"message": "Session deleted successfully"}


# ============== Health Check ==============

@router.get("/health")
async def chat_health():
    """Check chat service health."""
    return {
        "status": "healthy",
        "sessions": len(chat_manager.sessions),
        "llm_available": _explainer is not None,
    }