import logging
from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.models.finding import Finding
from app.services.llm import AIRemediator
from app.utils.redaction import redact_finding_context

logger = logging.getLogger(__name__)

@celery.task(bind=True, name="generate_ai_fix")
def generate_ai_fix(self, finding_id: str):
    logger.info(f"Generating AI fix for finding: {finding_id}")
    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error("Finding not found")
            raise ValueError("Finding not found")
            
        remediator = AIRemediator()
        
        # Prepare context for the AI, ensuring secrets are redacted before transmission!
        evidence_data = {"evidence": finding.evidence} if finding.evidence else {}
        redacted_context = redact_finding_context(evidence_data)
        evidence_str = str(redacted_context.get("evidence", "No specific code evidence provided."))
        
        cwe_str = finding.cwe or "Unknown CWE"
        
        # Generate the fix
        ai_response = remediator.generate_fix(
            finding_title=finding.title,
            cwe=cwe_str,
            evidence=evidence_str
        )
        
        # Update DB - Advice generation must not automatically confirm or mark fixed
        finding.remediation_plan = ai_response
        db.commit()
        
        logger.info(f"AI Remediation generated for finding {finding_id}")
        return f"Success: AI Remediation generated."
        
    except Exception as e:
        logger.error(f"AI generation failed: {str(e)}")
        db.rollback()
        raise  # Explicitly propagate so Celery treats it as a failure
    finally:
        db.close()
