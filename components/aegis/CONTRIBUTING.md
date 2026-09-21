# Contributing to AEGIS

Thank you for your interest in contributing to AEGIS! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)

---

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a branch** for your changes
4. **Make your changes**
5. **Test your changes**
6. **Submit a pull request**

---

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 18+
- npm or yarn
- Git

### Initial Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/aegis.git
cd aegis

# Add upstream remote
git remote add upstream https://github.com/originalowner/aegis.git

# Install backend dependencies
cd backend
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Install frontend dependencies
cd ../frontend
npm install

# Run the application
cd ..
./start.sh
```

---

## Project Structure

```
aegis/
├── backend/
│   └── src/aegis/
│       ├── api/          # FastAPI routes
│       ├── policy/       # Policy engine
│       ├── audit/        # Audit logging
│       ├── simulator/    # Attack scenarios
│       └── db.py         # Database models
├── frontend/
│   └── src/
│       ├── components/   # React components
│       └── App.jsx       # Main app
└── docs/                 # Documentation
```

---

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-new-detection-method`
- `fix/trust-score-calculation`
- `docs/update-api-documentation`
- `refactor/policy-engine`

### Commit Messages

Follow conventional commits:

```
type(scope): subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(investigation): add individual agent restore capability

fix(trust): correct trust score calculation after purge

docs(readme): add installation instructions
```

---

## Testing

### Backend Tests

```bash
cd backend
pytest tests/
```

### Frontend Tests

```bash
cd frontend
npm test
```

### Manual Testing

1. Start the application: `./start.sh`
2. Test all features:
   - Issue new agent identity
   - Run security scenarios
   - Execute global purge
   - Click revoked agents
   - Restore agents
   - Search audit logs

---

## Submitting Changes

### Pull Request Process

1. **Update your fork**
```bash
git fetch upstream
git checkout main
git merge upstream/main
```

2. **Create a feature branch**
```bash
git checkout -b feature/your-feature-name
```

3. **Make your changes and commit**
```bash
git add .
git commit -m "feat(scope): description"
```

4. **Push to your fork**
```bash
git push origin feature/your-feature-name
```

5. **Create Pull Request**
   - Go to GitHub
   - Click "New Pull Request"
   - Select your branch
   - Fill in the PR template
   - Submit

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Backend tests pass
- [ ] Frontend tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
```

---

## Style Guidelines

### Python (Backend)

Follow PEP 8:

```python
# Good
def evaluate_policy(agent_id: str, intent: str) -> dict:
    """Evaluate policy for given agent and intent."""
    result = policy_engine.check(agent_id, intent)
    return result

# Bad
def evaluatePolicy(agentId,intent):
    result=policy_engine.check(agentId,intent)
    return result
```

**Tools**:
- `black` for formatting
- `flake8` for linting
- `mypy` for type checking

### JavaScript/React (Frontend)

Follow Airbnb style guide:

```javascript
// Good
const WorkloadNodes = ({ agents }) => {
  const [selectedAgent, setSelectedAgent] = useState(null);
  
  return (
    <div className="space-y-10">
      {agents.map(agent => (
        <AgentCard key={agent.id} agent={agent} />
      ))}
    </div>
  );
};

// Bad
const WorkloadNodes = (props) => {
  var selectedAgent = null;
  return <div>{props.agents.map(a => <AgentCard agent={a} />)}</div>;
};
```

**Tools**:
- `eslint` for linting
- `prettier` for formatting

### Documentation

- Use clear, concise language
- Include code examples
- Add diagrams where helpful
- Keep README up to date

---

## Areas for Contribution

### High Priority

- [ ] Additional security scenarios
- [ ] Enhanced DLP patterns
- [ ] Policy testing framework
- [ ] Performance optimizations
- [ ] Mobile-responsive UI

### Medium Priority

- [ ] Additional detection mechanisms
- [ ] Export/import policies
- [ ] Agent grouping
- [ ] Custom dashboards
- [ ] Notification system

### Documentation

- [ ] Video tutorials
- [ ] Integration examples
- [ ] Best practices guide
- [ ] Troubleshooting guide
- [ ] API client libraries

### AEGIS v2 Features

See [AEGIS_V2_ROADMAP.md](docs/AEGIS_V2_ROADMAP.md) for planned enhancements:

- Intent namespaces
- Intent hierarchy
- System-computed confidence
- Entropy-based DLP
- Risk budgets
- Tiered approvals
- Multi-dimensional trust
- Model profiles
- Policy CI/CD

---

## Questions?

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues and PRs first

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to AEGIS! 🛡️
