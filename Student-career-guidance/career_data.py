# Expanded dictionary for software & IT career fields

CAREER_DETAILS = {
    "Software Developer": {
        "description": "Software Developers design, develop, test, and maintain software applications using programming languages and frameworks to meet user needs.",
        "day_in_life": "Daily coding, debugging, attending team standups, reviewing code, and building features.",
        "avg_salary": "₹8,00,000 - ₹16,00,000 P.A.",
        "required_skills": ["Python, Java, or C++", "Data Structures & Algorithms", "Version Control (Git)", "Databases (SQL/NoSQL)"],
        "career_path": ["Junior Developer", "Senior Developer", "Tech Lead", "Engineering Manager"],
        "resources": [
            {"name": "freeCodeCamp Curriculum", "url": "#"},
            {"name": "LeetCode Challenges", "url": "#"}
        ]
    },
    "Frontend Developer": {
        "description": "Frontend Developers build user interfaces and ensure smooth user experiences using web technologies like HTML, CSS, JavaScript, and modern frameworks.",
        "day_in_life": "Working on UI components, collaborating with designers, fixing bugs, and ensuring responsive design.",
        "avg_salary": "₹5,00,000 - ₹12,00,000 P.A.",
        "required_skills": ["HTML/CSS", "JavaScript", "React/Angular/Vue", "Responsive Design"],
        "career_path": ["Junior Frontend Developer", "Frontend Engineer", "UI Lead", "Frontend Architect"],
        "resources": [
            {"name": "Frontend Mentor", "url": "#"},
            {"name": "MDN Web Docs", "url": "#"}
        ]
    },
    "Backend Developer": {
        "description": "Backend Developers work on server-side applications, APIs, and database management to power web and mobile apps.",
        "day_in_life": "Building APIs, managing databases, writing server logic, optimizing performance.",
        "avg_salary": "₹6,00,000 - ₹14,00,000 P.A.",
        "required_skills": ["Node.js, Java, Python", "Databases", "API Development", "Authentication"],
        "career_path": ["Junior Backend Dev", "Backend Engineer", "Lead Engineer", "CTO"],
        "resources": [
            {"name": "Backend Roadmap", "url": "#"},
            {"name": "System Design Primer", "url": "#"}
        ]
    },
    "Full Stack Developer": {
        "description": "Full Stack Developers handle both frontend and backend tasks, making them versatile engineers.",
        "day_in_life": "Switching between UI and backend work, debugging, deployment.",
        "avg_salary": "₹7,00,000 - ₹18,00,000 P.A.",
        "required_skills": ["HTML/CSS/JS", "Node.js/Django", "Databases", "DevOps basics"],
        "career_path": ["Full Stack Engineer", "Tech Lead", "Engineering Manager"],
        "resources": [
            {"name": "Full Stack Open Course", "url": "#"}
        ]
    },
    "UI/UX Designer": {
        "description": "UI/UX Designers create intuitive and visually appealing digital interfaces, focusing on usability and accessibility.",
        "day_in_life": "Design wireframes, user flows, collaborate with devs, usability testing.",
        "avg_salary": "₹6,00,000 - ₹15,00,000 P.A.",
        "required_skills": ["Figma/Sketch", "Design Principles", "Prototyping", "User Research"],
        "career_path": ["UI/UX Intern", "Designer", "Senior Designer", "Design Lead"],
        "resources": [
            {"name": "Interaction Design Foundation", "url": "#"}
        ]
    },
    "DevOps Engineer": {
        "description": "DevOps Engineers bridge development and operations, focusing on automation, CI/CD pipelines, and infrastructure.",
        "day_in_life": "Managing deployments, monitoring systems, automating workflows, ensuring uptime.",
        "avg_salary": "₹8,00,000 - ₹20,00,000 P.A.",
        "required_skills": ["Linux", "Docker/Kubernetes", "CI/CD (Jenkins, GitHub Actions)", "AWS/GCP/Azure"],
        "career_path": ["DevOps Engineer", "Cloud Engineer", "Site Reliability Engineer", "DevOps Architect"],
        "resources": [
            {"name": "AWS Training", "url": "#"},
            {"name": "Kubernetes Docs", "url": "#"}
        ]
    },
    "Cloud Architect": {
        "description": "Cloud Architects design and oversee cloud computing strategies for enterprises, ensuring scalable, secure, and cost-effective solutions.",
        "day_in_life": "Designing cloud systems, setting up security, collaborating with DevOps.",
        "avg_salary": "₹12,00,000 - ₹30,00,000 P.A.",
        "required_skills": ["AWS/Azure/GCP", "Networking", "Security", "Infrastructure as Code"],
        "career_path": ["Cloud Engineer", "Cloud Architect", "Chief Cloud Officer"],
        "resources": [
            {"name": "Azure Solutions Architect Guide", "url": "#"}
        ]
    },
    "AI Engineer": {
        "description": "AI Engineers build intelligent systems, focusing on deep learning, NLP, and computer vision applications.",
        "day_in_life": "Data preprocessing, training ML/DL models, deploying AI systems.",
        "avg_salary": "₹10,00,000 - ₹28,00,000 P.A.",
        "required_skills": ["Python", "TensorFlow/PyTorch", "NLP", "Computer Vision", "MLOps"],
        "career_path": ["ML Engineer", "AI Engineer", "AI Architect", "Head of AI"],
        "resources": [
            {"name": "fast.ai", "url": "#"},
            {"name": "Stanford AI Course", "url": "#"}
        ]
    },
    "QA Engineer": {
        "description": "QA Engineers ensure the quality of software through manual and automated testing.",
        "day_in_life": "Writing test cases, running automated scripts, logging bugs.",
        "avg_salary": "₹4,00,000 - ₹10,00,000 P.A.",
        "required_skills": ["Selenium", "Test Automation", "JIRA", "Attention to Detail"],
        "career_path": ["QA Tester", "QA Engineer", "QA Lead", "QA Manager"],
        "resources": [
            {"name": "Test Automation University", "url": "#"}
        ]
    },
    "Database Administrator": {
        "description": "DBAs manage databases, ensuring data availability, performance, and security.",
        "day_in_life": "Managing backups, optimizing queries, monitoring performance.",
        "avg_salary": "₹6,00,000 - ₹15,00,000 P.A.",
        "required_skills": ["SQL", "Oracle/MySQL/Postgres", "Backup/Recovery", "Performance Tuning"],
        "career_path": ["Junior DBA", "Senior DBA", "Database Architect"],
        "resources": [
            {"name": "SQLZoo", "url": "#"}
        ]
    },
    "Game Developer": {
        "description": "Game Developers design and build interactive video games using game engines like Unity or Unreal.",
        "day_in_life": "Coding gameplay features, testing, collaborating with artists.",
        "avg_salary": "₹5,00,000 - ₹14,00,000 P.A.",
        "required_skills": ["C++/C#", "Unity/Unreal Engine", "Game Physics", "3D Math"],
        "career_path": ["Junior Game Dev", "Game Programmer", "Lead Developer"],
        "resources": [
            {"name": "Unity Learn", "url": "#"}
        ]
    }
}

def get_career_details(career_name):
    return CAREER_DETAILS.get(career_name, {
        "description": "Detailed information for this career is currently unavailable.",
        "day_in_life": "Information not available.",
        "avg_salary": "N/A",
        "required_skills": ["Information not available."],
        "career_path": ["Information not available."],
        "resources": []
    })
