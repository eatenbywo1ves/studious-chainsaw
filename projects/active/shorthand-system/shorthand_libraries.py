"""
Specialized Shorthand Response Libraries
Pre-built collections for different domains and use cases
"""

from shorthand_autoresponder import (
    ShorthandEngine, 
    ShorthandRule, 
    ResponseCategory, 
    TriggerType,
    ResponseTemplate
)
import json


class ResponseLibrary:
    """Base class for response libraries"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.rules = []
        self.templates = []


class ITSupportLibrary(ResponseLibrary):
    """IT Support and helpdesk responses"""
    
    def __init__(self):
        super().__init__("IT Support", "Common IT support responses and troubleshooting")
        
        self.rules = [
            # Quick acknowledgments
            ("ack", "I've received your request and I'm looking into it now.", ResponseCategory.SUPPORT),
            ("wrk", "I'm working on this issue and will update you shortly.", ResponseCategory.SUPPORT),
            ("rsv", "This issue has been resolved. Please let me know if you need anything else.", ResponseCategory.SUPPORT),
            
            # Troubleshooting
            ("rbt", "Have you tried restarting your computer? This often resolves common issues.", ResponseCategory.TECHNICAL),
            ("clr", "Please try clearing your browser cache and cookies, then try again.", ResponseCategory.TECHNICAL),
            ("upd", "Please ensure all software is up to date and try again.", ResponseCategory.TECHNICAL),
            ("chknet", "Please check your network connection and try again.", ResponseCategory.NETWORK),
            
            # Escalation
            ("esc1", "I'm escalating this to our Level 2 support team for further investigation.", ResponseCategory.SUPPORT),
            ("esc2", "This requires specialized attention. I'm escalating to our senior technicians.", ResponseCategory.SUPPORT),
            ("mgr", "I'll need to involve my manager for this request. They'll contact you shortly.", ResponseCategory.SUPPORT),
            
            # Common issues
            ("pwreset", "To reset your password:\n1. Go to the login page\n2. Click 'Forgot Password'\n3. Follow the email instructions\n4. Create a new strong password", ResponseCategory.SECURITY),
            ("vpnhelp", "To connect to VPN:\n1. Open VPN client\n2. Enter your credentials\n3. Select the appropriate server\n4. Click Connect", ResponseCategory.NETWORK),
            ("prntfix", "For printer issues:\n1. Check cable connections\n2. Ensure printer is powered on\n3. Clear print queue\n4. Reinstall printer drivers if needed", ResponseCategory.TECHNICAL),
            
            # Status updates
            ("prog25", "Update: 25% complete. Still investigating the root cause.", ResponseCategory.SUPPORT),
            ("prog50", "Update: 50% complete. I've identified the issue and working on a solution.", ResponseCategory.SUPPORT),
            ("prog75", "Update: 75% complete. Solution is being implemented.", ResponseCategory.SUPPORT),
            ("prog100", "Update: 100% complete. Issue has been resolved.", ResponseCategory.SUPPORT),
            
            # Security responses
            ("secalrt", "[SECURITY] Potential security issue detected. Please change your password immediately and enable 2FA.", ResponseCategory.SECURITY),
            ("phish", "This appears to be a phishing attempt. Do not click any links. Forward the email to security@company.com", ResponseCategory.SECURITY),
            ("malware", "Potential malware detected. Disconnect from network immediately. Running security scan.", ResponseCategory.EMERGENCY),
        ]
        
        self.templates = [
            {
                "name": "ticket_created",
                "template": "Ticket #{ticket_id} has been created for your issue: {description}\nExpected resolution time: {eta}",
                "variables": ["ticket_id", "description", "eta"],
                "tags": ["ticket", "support"]
            },
            {
                "name": "remote_session",
                "template": "I'll need to connect remotely to assist. Please:\n1. Download TeamViewer from {link}\n2. Share the session ID: {session_id}\n3. I'll connect shortly",
                "variables": ["link", "session_id"],
                "tags": ["remote", "support"]
            }
        ]


class CustomerServiceLibrary(ResponseLibrary):
    """Customer service and sales responses"""
    
    def __init__(self):
        super().__init__("Customer Service", "Professional customer service responses")
        
        self.rules = [
            # Greetings
            ("greet", "Hello! Thank you for contacting us. How may I assist you today?", ResponseCategory.GREETING),
            ("welc", "Welcome! We're happy to help you with any questions or concerns.", ResponseCategory.GREETING),
            
            # Apologies
            ("sry", "I sincerely apologize for the inconvenience. Let me help resolve this for you.", ResponseCategory.CUSTOMER),
            ("regret", "We regret that you've had this experience. Your satisfaction is our priority.", ResponseCategory.CUSTOMER),
            
            # Order status
            ("ordstat", "I'll check your order status right away. May I have your order number?", ResponseCategory.CUSTOMER),
            ("ship", "Your order has been shipped and should arrive within {days} business days.", ResponseCategory.CUSTOMER),
            ("track", "You can track your order using this link: {tracking_url}", ResponseCategory.CUSTOMER),
            
            # Returns/Refunds
            ("rtrn", "I'll help you with your return. Our return policy allows returns within 30 days of purchase.", ResponseCategory.CUSTOMER),
            ("rfnd", "Your refund has been processed and should appear in your account within 3-5 business days.", ResponseCategory.CUSTOMER),
            
            # Satisfaction
            ("sat", "Your satisfaction is important to us. How can we make this right?", ResponseCategory.CUSTOMER),
            ("fbk", "Thank you for your feedback. We'll use it to improve our services.", ResponseCategory.CUSTOMER),
            
            # Closing
            ("cls", "Is there anything else I can help you with today?", ResponseCategory.CUSTOMER),
            ("thx", "Thank you for choosing us. Have a wonderful day!", ResponseCategory.CUSTOMER),
        ]


class DeveloperLibrary(ResponseLibrary):
    """Developer and coding responses"""
    
    def __init__(self):
        super().__init__("Developer", "Code snippets and developer communications")
        
        self.rules = [
            # Git commands
            ("gits", "git status", ResponseCategory.CODE),
            ("gitc", "git add . && git commit -m \"{message}\"", ResponseCategory.CODE),
            ("gitp", "git push origin {branch}", ResponseCategory.CODE),
            ("gitpl", "git pull origin {branch}", ResponseCategory.CODE),
            ("gitb", "git checkout -b {branch_name}", ResponseCategory.CODE),
            ("gitm", "git merge {branch}", ResponseCategory.CODE),
            
            # Code review
            ("lgtm", "Looks good to me! Approved. ✅", ResponseCategory.CODE),
            ("nit", "Nit: Minor suggestion (non-blocking): ", ResponseCategory.CODE),
            ("block", "Blocking issue: This needs to be addressed before merge.", ResponseCategory.CODE),
            ("refac", "Consider refactoring this for better readability/performance.", ResponseCategory.CODE),
            
            # Python snippets
            ("pyimport", "import os\nimport sys\nimport json\nimport requests\nfrom datetime import datetime", ResponseCategory.CODE),
            ("pymain", "if __name__ == \"__main__\":\n    main()", ResponseCategory.CODE),
            ("pytry", "try:\n    {code}\nexcept Exception as e:\n    print(f'Error: {e}')", ResponseCategory.CODE),
            ("pylog", "import logging\nlogging.basicConfig(level=logging.INFO)\nlogger = logging.getLogger(__name__)", ResponseCategory.CODE),
            
            # JavaScript snippets
            ("jsasync", "async function {name}() {\n    try {\n        const result = await {promise};\n        return result;\n    } catch (error) {\n        console.error(error);\n    }\n}", ResponseCategory.CODE),
            ("jsmap", ".map(item => {\n    return {transformation};\n})", ResponseCategory.CODE),
            ("jsfilter", ".filter(item => item.{property} === {value})", ResponseCategory.CODE),
            
            # SQL snippets
            ("sqlsel", "SELECT * FROM {table} WHERE {condition};", ResponseCategory.CODE),
            ("sqlins", "INSERT INTO {table} ({columns}) VALUES ({values});", ResponseCategory.CODE),
            ("sqlupd", "UPDATE {table} SET {column} = {value} WHERE {condition};", ResponseCategory.CODE),
            ("sqldel", "DELETE FROM {table} WHERE {condition};", ResponseCategory.CODE),
            ("sqljoin", "SELECT * FROM {table1} JOIN {table2} ON {table1}.{col} = {table2}.{col};", ResponseCategory.CODE),
            
            # Documentation
            ("docpy", "'''\n{description}\n\nArgs:\n    {param}: {param_desc}\n\nReturns:\n    {return_desc}\n'''", ResponseCategory.DOCUMENTATION),
            ("docjs", "/**\n * {description}\n * @param {{type}} {param} - {param_desc}\n * @returns {{type}} {return_desc}\n */", ResponseCategory.DOCUMENTATION),
            
            # Common responses
            ("wip", "Work in progress - not ready for review yet 🚧", ResponseCategory.PROJECT),
            ("rdy", "Ready for review! Please take a look when you have time.", ResponseCategory.PROJECT),
            ("fixed", "Fixed in commit {commit_hash}", ResponseCategory.CODE),
            ("tested", "Tested locally and all tests pass ✅", ResponseCategory.CODE),
        ]


class EmailLibrary(ResponseLibrary):
    """Professional email templates"""
    
    def __init__(self):
        super().__init__("Email", "Professional email templates and responses")
        
        self.rules = [
            # Openings
            ("dearcol", "Dear Colleagues,\n\nI hope this message finds you well.", ResponseCategory.EMAIL),
            ("hi", "Hi {name},\n\nI hope you're having a great day.", ResponseCategory.EMAIL),
            ("follow", "I'm following up on our previous conversation about {topic}.", ResponseCategory.EMAIL),
            
            # Body templates
            ("mtgreq", "I'd like to schedule a meeting to discuss {topic}. Are you available {day} at {time}?", ResponseCategory.MEETING),
            ("update", "I wanted to provide you with an update on {project}:\n\n• {point1}\n• {point2}\n• {point3}", ResponseCategory.PROJECT),
            ("request", "I'm writing to request {item}. This is needed for {reason} by {deadline}.", ResponseCategory.EMAIL),
            
            # Responses
            ("conf", "Thank you for your email. I can confirm that {action}.", ResponseCategory.EMAIL),
            ("recv", "Thank you for sending {item}. I've received it and will review shortly.", ResponseCategory.EMAIL),
            ("appr", "This looks good. Approved to proceed.", ResponseCategory.EMAIL),
            
            # Closings
            ("regards", "Best regards,\n{name}", ResponseCategory.EMAIL),
            ("sincere", "Sincerely,\n{name}\n{title}", ResponseCategory.EMAIL),
            ("thanks", "Thanks in advance for your help.\n\nBest,\n{name}", ResponseCategory.EMAIL),
            
            # Out of office
            ("ooo", "I'm currently out of office and will return on {date}. For urgent matters, please contact {alternate_contact}.", ResponseCategory.EMAIL),
            ("vacation", "I'm on vacation from {start_date} to {end_date}. I'll respond to your email upon my return.", ResponseCategory.EMAIL),
        ]


class NetworkSecurityLibrary(ResponseLibrary):
    """Network and security monitoring responses"""
    
    def __init__(self):
        super().__init__("Network Security", "Network monitoring and security alerts")
        
        self.rules = [
            # Alerts
            ("alrt", "[ALERT] Anomaly detected: {description} at {timestamp}", ResponseCategory.SECURITY),
            ("crit", "[CRITICAL] Immediate action required: {issue}", ResponseCategory.EMERGENCY),
            ("warn", "[WARNING] Potential issue detected: {description}", ResponseCategory.SECURITY),
            ("info", "[INFO] System notification: {message}", ResponseCategory.NETWORK),
            
            # Network status
            ("netup", "Network services are operational. All systems green.", ResponseCategory.NETWORK),
            ("netdown", "Network outage detected. Investigating root cause.", ResponseCategory.EMERGENCY),
            ("netdeg", "Network degradation detected. Performance may be impacted.", ResponseCategory.NETWORK),
            
            # Security responses
            ("breach", "[SECURITY BREACH] Unauthorized access detected from IP: {ip}. Initiating lockdown.", ResponseCategory.EMERGENCY),
            ("ddos", "[DDoS ATTACK] Distributed denial of service detected. Activating mitigation.", ResponseCategory.EMERGENCY),
            ("scan", "[PORT SCAN] Scanning activity detected from {source_ip}. Blocking source.", ResponseCategory.SECURITY),
            
            # Commands
            ("blkip", "iptables -A INPUT -s {ip} -j DROP", ResponseCategory.SECURITY),
            ("chkport", "netstat -tuln | grep {port}", ResponseCategory.NETWORK),
            ("tcpdump", "tcpdump -i {interface} -w capture.pcap", ResponseCategory.NETWORK),
            ("nmap", "nmap -sS -sV -O {target}", ResponseCategory.NETWORK),
            
            # Incident response
            ("ir1", "Incident detected. Starting initial response procedure.", ResponseCategory.EMERGENCY),
            ("ir2", "Incident contained. Assessing damage and collecting evidence.", ResponseCategory.EMERGENCY),
            ("ir3", "Incident resolved. Conducting post-mortem analysis.", ResponseCategory.SECURITY),
        ]


class SocialMediaLibrary(ResponseLibrary):
    """Social media and community management responses"""
    
    def __init__(self):
        super().__init__("Social Media", "Social media engagement and community responses")
        
        self.rules = [
            # Engagement
            ("tyfol", "Thank you for following! We're excited to have you in our community!", ResponseCategory.SOCIAL),
            ("tylike", "Thanks for the love! ❤️", ResponseCategory.SOCIAL),
            ("tyshare", "Thank you for sharing! We appreciate your support!", ResponseCategory.SOCIAL),
            
            # Community
            ("welcome", "Welcome to our community! Feel free to ask questions anytime.", ResponseCategory.SOCIAL),
            ("congrats", "Congratulations! 🎉 That's an amazing achievement!", ResponseCategory.SOCIAL),
            ("inspire", "This is so inspiring! Thank you for sharing your story.", ResponseCategory.SOCIAL),
            
            # Content
            ("newpost", "New post alert! 🔔 Check out our latest: {link}", ResponseCategory.SOCIAL),
            ("blog", "Read our latest blog post: {title} - {link}", ResponseCategory.SOCIAL),
            ("video", "New video up! 🎥 Watch here: {link}", ResponseCategory.SOCIAL),
            
            # Support
            ("dm", "Thanks for reaching out! Please DM us with more details and we'll help.", ResponseCategory.SOCIAL),
            ("help", "We're here to help! What can we do for you?", ResponseCategory.SOCIAL),
        ]


def load_library(library_name: str, engine: ShorthandEngine):
    """Load a specific library into the engine"""
    
    libraries = {
        "it_support": ITSupportLibrary(),
        "customer_service": CustomerServiceLibrary(),
        "developer": DeveloperLibrary(),
        "email": EmailLibrary(),
        "network_security": NetworkSecurityLibrary(),
        "social_media": SocialMediaLibrary()
    }
    
    if library_name not in libraries:
        print(f"Library '{library_name}' not found")
        return False
    
    library = libraries[library_name]
    
    # Load rules
    for trigger, expansion, category in library.rules:
        rule = ShorthandRule(
            trigger=trigger,
            expansion=expansion,
            category=category,
            trigger_type=TriggerType.EXACT,
            priority=5
        )
        engine.add_rule(rule)
    
    # Load templates
    for template_data in library.templates:
        engine.create_template(
            name=template_data["name"],
            template=template_data["template"],
            category=ResponseCategory.SUPPORT,
            variables=template_data.get("variables", []),
            tags=template_data.get("tags", [])
        )
    
    print(f"Loaded {library.name} library with {len(library.rules)} rules")
    return True


def create_custom_library(name: str, rules: list) -> dict:
    """Create a custom library from user-defined rules"""
    library = {
        "name": name,
        "description": "Custom user-defined library",
        "rules": [],
        "created": str(datetime.datetime.now())
    }
    
    for rule_data in rules:
        if isinstance(rule_data, tuple) and len(rule_data) >= 2:
            trigger, expansion = rule_data[:2]
            category = rule_data[2] if len(rule_data) > 2 else ResponseCategory.CUSTOM
            
            library["rules"].append({
                "trigger": trigger,
                "expansion": expansion,
                "category": category.value if isinstance(category, ResponseCategory) else category
            })
    
    # Save to file
    filename = f"custom_library_{name.lower().replace(' ', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(library, f, indent=2)
    
    return library


# Example presets for specific industries
INDUSTRY_PRESETS = {
    "healthcare": [
        ("hipaa", "This information is protected under HIPAA privacy regulations.", ResponseCategory.SECURITY),
        ("apt", "Your appointment is scheduled for {date} at {time}.", ResponseCategory.CUSTOMER),
        ("rx", "Your prescription is ready for pickup at the pharmacy.", ResponseCategory.CUSTOMER),
        ("emr", "Electronic Medical Record updated successfully.", ResponseCategory.TECHNICAL),
    ],
    
    "finance": [
        ("kyc", "Know Your Customer verification required for this transaction.", ResponseCategory.SECURITY),
        ("aml", "Anti-Money Laundering check in progress.", ResponseCategory.SECURITY),
        ("txn", "Transaction ID: {id} processed successfully.", ResponseCategory.CUSTOMER),
        ("bal", "Your current balance is: {amount}", ResponseCategory.CUSTOMER),
    ],
    
    "education": [
        ("hw", "Homework assignment due: {date}", ResponseCategory.PROJECT),
        ("grade", "Grade posted: {score}/{total}", ResponseCategory.CUSTOMER),
        ("syllabus", "Please refer to the syllabus for course requirements.", ResponseCategory.DOCUMENTATION),
        ("office", "Office hours: {days} from {start_time} to {end_time}", ResponseCategory.MEETING),
    ],
    
    "legal": [
        ("nda", "Non-Disclosure Agreement required before proceeding.", ResponseCategory.SECURITY),
        ("conf", "This communication is confidential and attorney-client privileged.", ResponseCategory.SECURITY),
        ("deadline", "Filing deadline: {date}. All documents must be submitted by then.", ResponseCategory.PROJECT),
    ],
}


if __name__ == "__main__":
    # Demo loading libraries
    print("Available Response Libraries:")
    print("-" * 40)
    
    engine = ShorthandEngine()
    
    # Load IT Support library
    load_library("it_support", engine)
    load_library("developer", engine)
    
    # Test some expansions
    test_cases = [
        "I'll esc1 this issue.",
        "gits and then gitc with message",
        "lgtm! Just one nit about the variable naming."
    ]
    
    print("\nTesting expansions:")
    for test in test_cases:
        expanded = engine.expand(test)
        print(f"  '{test}' -> '{expanded}'")
    
    print("\nLibraries loaded successfully!")