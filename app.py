import streamlit as st
import os
import json
from groq import Groq

# Page config
st.set_page_config(
    page_title="LLM Security Helper",
    page_icon="🔒",
    layout="wide"
)

# Initialize Groq client
@st.cache_resource
def get_groq_client():
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        st.error("⚠️ GROQ_API_KEY not found in environment variables!")
        st.info("Get your FREE API key at: https://console.groq.com/")
        st.stop()
    return Groq(api_key=api_key)

client = get_groq_client()

# Title and description
st.title("🔒 LLM Security Helper")
st.markdown("**Analyze code vulnerabilities and GenAI app security risks**")
st.markdown("---")

# Sidebar for API key setup instructions
with st.sidebar:
    st.header("⚙️ Setup Instructions")
    st.markdown("""
    **To run this app:**
    
    1. Get FREE Groq API key:
    - Visit https://console.groq.com/
    - Sign up (free)
    - Copy your API key
    
    2. Set your API key:
    ```bash
    # PowerShell
    $env:GROQ_API_KEY='your-key-here'
    
    # Mac/Linux
    export GROQ_API_KEY='your-key-here'
    ```
    
    3. Run the app:
    ```bash
    python -m streamlit run app.py
    ```
    """)
    
    st.markdown("---")
    st.markdown("**Model:** llama-3.3-70b-versatile(via Groq)")
    st.markdown("**Cost:** FREE! 🎉")
    st.markdown("**Features:**")
    st.markdown("- Code vulnerability analysis")
    st.markdown("- GenAI security risk mapping")

# Create tabs for the two parts
tab1, tab2 = st.tabs(["📝 Part 1: Code Security Analysis", "🎯 Part 2: GenAI Vulnerability Mapping"])

# ==================== PART 1: Code Security Analysis ====================
with tab1:
    st.header("Code → Security Fixes")
    st.markdown("Paste your code below to identify security vulnerabilities and get recommended fixes.")
    
    code_input = st.text_area(
        "Code Input:",
        height=300,
        placeholder="Paste your code here (e.g., Python, JavaScript, SQL, etc.)",
        key="code_input"
    )
    
    analyze_code_btn = st.button("🔍 Analyze Code", key="analyze_code", type="primary")
    
    if analyze_code_btn:
        if not code_input.strip():
            st.warning("Please enter some code to analyze.")
        else:
            with st.spinner("Analyzing code for security vulnerabilities..."):
                try:
                    # Call Groq API for code analysis
                    chat_completion = client.chat.completions.create(
                        messages=[
                            {
                                "role": "user",
                                "content": f"""You are a security expert. Analyze the following code for SECURITY VULNERABILITIES ONLY.

Code to analyze:
```
{code_input}
```

Provide a detailed analysis in the following JSON format:
{{
    "summary": "Brief overview of security issues found",
    "vulnerabilities": [
        {{
            "severity": "Critical|High|Medium|Low",
            "type": "Vulnerability type (e.g., SQL Injection, XSS, etc.)",
            "description": "Detailed description of the vulnerability",
            "vulnerable_code": "The specific code snippet that's vulnerable",
            "fix": "Recommended fix with code example",
            "cwe_id": "CWE identifier if applicable"
        }}
    ],
    "secure_code_example": "Full corrected version of the code with all fixes applied"
}}

Focus ONLY on security issues, not code quality or refactoring suggestions. Be specific and actionable."""
                            }
                        ],
                        model="llama-3.3-70b-versatile",
                        temperature=0.3,
                        max_tokens=4000,
                    )
                    
                    # Parse response
                    response_text = chat_completion.choices[0].message.content
                    
                    # Try to extract JSON from response
                    try:
                        # Find JSON in the response
                        json_start = response_text.find('{')
                        json_end = response_text.rfind('}') + 1
                        if json_start != -1 and json_end > json_start:
                            json_str = response_text[json_start:json_end]
                            analysis = json.loads(json_str)
                        else:
                            # Fallback to plain text display
                            analysis = None
                    except:
                        analysis = None
                    
                    # Display results
                    st.success("✅ Analysis Complete")
                    
                    if analysis:
                        # Structured display
                        st.subheader("📊 Summary")
                        st.info(analysis.get("summary", "No summary available"))
                        
                        if analysis.get("vulnerabilities"):
                            st.subheader("🚨 Vulnerabilities Found")
                            
                            for i, vuln in enumerate(analysis["vulnerabilities"], 1):
                                severity = vuln.get("severity", "Unknown")
                                severity_color = {
                                    "Critical": "🔴",
                                    "High": "🟠",
                                    "Medium": "🟡",
                                    "Low": "🟢"
                                }.get(severity, "⚪")
                                
                                with st.expander(f"{severity_color} {severity}: {vuln.get('type', 'Unknown')}"):
                                    st.markdown(f"**Description:**  \n{vuln.get('description', 'N/A')}")
                                    
                                    if vuln.get("cwe_id"):
                                        st.markdown(f"**CWE ID:** {vuln['cwe_id']}")
                                    
                                    if vuln.get("vulnerable_code"):
                                        st.markdown("**Vulnerable Code:**")
                                        st.code(vuln["vulnerable_code"], language="python")
                                    
                                    if vuln.get("fix"):
                                        st.markdown("**Recommended Fix:**")
                                        st.markdown(vuln["fix"])
                        else:
                            st.success("✅ No security vulnerabilities detected!")
                        
                        if analysis.get("secure_code_example"):
                            st.subheader("✨ Secure Code Example")
                            st.code(analysis["secure_code_example"], language="python")
                    else:
                        # Plain text fallback
                        st.markdown("### Analysis Results:")
                        st.markdown(response_text)
                    
                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")
                    st.exception(e)

# ==================== PART 2: GenAI Vulnerability Mapping ====================
with tab2:
    st.header("GenAI App Specs → Vulnerability Mapping")
    st.markdown("Describe your GenAI/Agentic application to identify potential security risks mapped to OWASP LLM Top 10 and ATLAS framework.")
    
    specs_input = st.text_area(
        "Application Specifications:",
        height=300,
        placeholder="Describe your GenAI/Agentic application:\n- What does it do?\n- What inputs does it take?\n- What external systems does it interact with?\n- How does it use LLMs?\n- What data does it handle?",
        key="specs_input"
    )
    
    analyze_specs_btn = st.button("🎯 Analyze Vulnerabilities", key="analyze_specs", type="primary")
    
    if analyze_specs_btn:
        if not specs_input.strip():
            st.warning("Please enter application specifications to analyze.")
        else:
            with st.spinner("Mapping vulnerabilities to OWASP LLM Top 10 and ATLAS..."):
                try:
                    # Call Groq API for GenAI security analysis
                    chat_completion = client.chat.completions.create(
                        messages=[
                            {
                                "role": "user",
                                "content": f"""You are an AI security expert specializing in LLM application security. Analyze the following GenAI/Agentic application specifications and identify potential security vulnerabilities.

Application Specifications:
{specs_input}

Provide a comprehensive security analysis mapped to BOTH:
1. OWASP Top 10 for LLM Applications (2023)
2. MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

Return your analysis in the following JSON format:
{{
    "app_summary": "Brief summary of the application and its security posture",
    "owasp_llm_vulnerabilities": [
        {{
            "owasp_category": "LLM01, LLM02, etc. with full name",
            "risk_level": "Critical|High|Medium|Low",
            "description": "Specific vulnerability in this application",
            "attack_scenario": "Concrete example of how this could be exploited",
            "mitigation": "Specific, actionable mitigation strategies",
            "detection": "How to detect this vulnerability or attack"
        }}
    ],
    "atlas_threats": [
        {{
            "atlas_technique": "Technique ID and name from ATLAS matrix",
            "tactic": "ATLAS tactic (e.g., Reconnaissance, Resource Development, etc.)",
            "description": "How this threat applies to the application",
            "attack_example": "Specific attack scenario",
            "countermeasures": "Technical countermeasures"
        }}
    ],
    "priority_risks": [
        "List of 3-5 highest priority risks to address immediately"
    ],
    "security_recommendations": [
        "Overall security recommendations specific to this application"
    ]
}}

Be specific, actionable, and relevant to the described application. Focus on realistic threats.

OWASP LLM Top 10 Reference:
- LLM01: Prompt Injection
- LLM02: Insecure Output Handling
- LLM03: Training Data Poisoning
- LLM04: Model Denial of Service
- LLM05: Supply Chain Vulnerabilities
- LLM06: Sensitive Information Disclosure
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance
- LLM10: Model Theft"""
                            }
                        ],
                        model="llama-3.3-70b-versatile",
                        temperature=0.3,
                        max_tokens=8000,
                    )
                    
                    # Parse response
                    response_text = chat_completion.choices[0].message.content
                    
                    # Try to extract JSON from response
                    try:
                        json_start = response_text.find('{')
                        json_end = response_text.rfind('}') + 1
                        if json_start != -1 and json_end > json_start:
                            json_str = response_text[json_start:json_end]
                            analysis = json.loads(json_str)
                        else:
                            analysis = None
                    except:
                        analysis = None
                    
                    # Display results
                    st.success("✅ Vulnerability Analysis Complete")
                    
                    if analysis:
                        # Application Summary
                        st.subheader("📋 Application Security Summary")
                        st.info(analysis.get("app_summary", "No summary available"))
                        
                        # Priority Risks
                        if analysis.get("priority_risks"):
                            st.subheader("🚨 Priority Risks")
                            for risk in analysis["priority_risks"]:
                                st.warning(f"⚠️ {risk}")
                        
                        # OWASP LLM Top 10 Vulnerabilities
                        if analysis.get("owasp_llm_vulnerabilities"):
                            st.subheader("🔴 OWASP LLM Top 10 Vulnerabilities")
                            
                            for vuln in analysis["owasp_llm_vulnerabilities"]:
                                risk_level = vuln.get("risk_level", "Unknown")
                                risk_emoji = {
                                    "Critical": "🔴",
                                    "High": "🟠",
                                    "Medium": "🟡",
                                    "Low": "🟢"
                                }.get(risk_level, "⚪")
                                
                                with st.expander(f"{risk_emoji} {vuln.get('owasp_category', 'Unknown')} - {risk_level} Risk"):
                                    st.markdown(f"**Description:**  \n{vuln.get('description', 'N/A')}")
                                    st.markdown(f"**Attack Scenario:**  \n{vuln.get('attack_scenario', 'N/A')}")
                                    st.markdown(f"**Mitigation:**  \n{vuln.get('mitigation', 'N/A')}")
                                    if vuln.get("detection"):
                                        st.markdown(f"**Detection:**  \n{vuln['detection']}")
                        
                        # ATLAS Threats
                        if analysis.get("atlas_threats"):
                            st.subheader("🎯 MITRE ATLAS Threat Mapping")
                            
                            for threat in analysis["atlas_threats"]:
                                with st.expander(f"🎯 {threat.get('atlas_technique', 'Unknown')} ({threat.get('tactic', 'Unknown')})"):
                                    st.markdown(f"**Tactic:** {threat.get('tactic', 'N/A')}")
                                    st.markdown(f"**Description:**  \n{threat.get('description', 'N/A')}")
                                    st.markdown(f"**Attack Example:**  \n{threat.get('attack_example', 'N/A')}")
                                    st.markdown(f"**Countermeasures:**  \n{threat.get('countermeasures', 'N/A')}")
                        
                        # Security Recommendations
                        if analysis.get("security_recommendations"):
                            st.subheader("✅ Security Recommendations")
                            for i, rec in enumerate(analysis["security_recommendations"], 1):
                                st.success(f"{i}. {rec}")
                    else:
                        # Plain text fallback
                        st.markdown("### Analysis Results:")
                        st.markdown(response_text)
                    
                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")
                    st.exception(e)

# Footer
st.markdown("---")
st.markdown("**Built with:** Streamlit + Groq (llama-3.3-70b-versatile) | **Security Frameworks:** OWASP LLM Top 10 + MITRE ATLAS")