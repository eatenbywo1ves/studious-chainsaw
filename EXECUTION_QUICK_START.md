# Phase 2 Quick Start Guide
**Ghidra Plugin Development - Start NOW**

---

## What is Phase 2?

**Weeks 5-12**: AI/ML-powered Ghidra plugin development
**Goal**: Release 3 production-grade plugins to community
**Method**: BMAD cycles for each plugin

---

## Phase 2 at a Glance

```
Week 5-6:  GhidrAssist   (16h) → AI analysis assistant
Week 7-9:  GhidraSimilarity (20h) → ML binary matching
Week 10-11: GhidraGo      (16h) → Golang analyzer
Week 12:    Integration   (8h)  → Suite release

Total: 120-150 hours (15-19 hrs/week)
```

---

## Prerequisites (Before Starting)

### 1. Phase 1 Complete
- ✅ Load testing validated (Week 1)
- ✅ Monitoring deployed (Week 1)
- ✅ CI/CD pipeline working (Week 2)
- ✅ Vault deployed (Week 3)

**If Phase 1 incomplete:** Finish Weeks 1-4 first

### 2. Development Environment

```bash
# Check Ghidra installed
ls "C:/Program Files/ghidra_11.0"

# Check Java 17+
java -version

# Check Gradle
gradle --version

# Check Git
git --version
```

**If missing:** Install before proceeding

### 3. Project Structure

```bash
cd C:\Users\Corbin\development

# Create Ghidra extensions directory
mkdir -p ghidra-extensions/GhidrAssist
mkdir -p ghidra-extensions/GhidraSimilarity
mkdir -p ghidra-extensions/GhidraGo

# Verify
ls ghidra-extensions/
```

---

## START HERE → Week 5, Day 1

### GhidrAssist BUILD Phase

#### Step 1: Create Plugin Structure (30 minutes)

```bash
cd development/ghidra-extensions/GhidrAssist

# Create directory structure
mkdir -p src/main/java/ghidrassist
mkdir -p src/main/resources
mkdir -p test/benchmarks
mkdir -p test/binaries

# Create build.gradle
cat > build.gradle << 'EOF'
plugins {
    id 'java'
}

group = 'com.catalyticcomputing'
version = '1.0.0'

sourceCompatibility = 17
targetCompatibility = 17

repositories {
    mavenCentral()
}

dependencies {
    // Ghidra dependencies (provided by Ghidra installation)
    compileOnly fileTree(dir: System.getenv('GHIDRA_INSTALL_DIR') + '/Ghidra/Framework', include: '**/*.jar')
    compileOnly fileTree(dir: System.getenv('GHIDRA_INSTALL_DIR') + '/Ghidra/Features', include: '**/*.jar')

    // Testing
    testImplementation 'org.junit.jupiter:junit-jupiter:5.9.0'
}

test {
    useJUnitPlatform()
}

task buildExtension(type: Zip) {
    from('src/main') {
        into 'ghidra_scripts'
    }
    archiveBaseName = 'GhidrAssist'
    archiveVersion = version
    destinationDirectory = file('dist')
}
EOF

# Verify
gradle tasks
```

---

#### Step 2: Create MCP Client (1 hour)

Copy the MCPClient.java from PHASE2_BMAD_PRODUCTION_ROADMAP.md into:
`src/main/java/ghidrassist/MCPClient.java`

**Test:**
```bash
gradle compileJava
```

Expected: No errors

---

#### Step 3: Create Function Explanation UI (2 hours)

Copy these files from the roadmap:
1. `FunctionExplanationAction.java`
2. `ExplanationPanel.java`

**Test:**
```bash
gradle build
```

Expected: Successful build

---

#### Step 4: Create Plugin Manifest (15 minutes)

File: `src/main/resources/extension.properties`

```properties
name=GhidrAssist
description=AI-powered analysis assistant with MCP integration
author=Catalytic Computing
createdOn=10/07/2025
version=1.0.0
```

File: `Module.manifest`

```
MODULE FILE VERSION: 1
MODULE NAME: GhidrAssist
MODULE FILE LICENSE: Apache-2.0
```

---

#### Step 5: Install & Test (30 minutes)

```bash
# Build extension
gradle buildExtension

# Copy to Ghidra
cp dist/GhidrAssist-1.0.0.zip "C:/Program Files/ghidra_11.0/Extensions/Ghidra/"

# Extract
cd "C:/Program Files/ghidra_11.0/Extensions/Ghidra/"
unzip GhidrAssist-1.0.0.zip

# Launch Ghidra
"C:/Program Files/ghidra_11.0/ghidraRun.bat"

# Enable plugin:
# File → Configure → Miscellaneous → GhidrAssist ✓
```

**Verify:**
- Open any binary
- Right-click on function
- See "GhidrAssist" menu

✅ **BUILD Phase Day 1 Complete!**

---

## Week 5 Full Schedule

### Monday (Day 1)
- [x] Plugin structure created
- [x] MCP client implemented
- [x] Function explanation UI created
- [ ] Tested in Ghidra

### Tuesday (Day 2)
- [ ] Variable renaming feature
- [ ] Batch rename dialog
- [ ] Integration testing

### Wednesday (Day 3)
- [ ] Vulnerability scanner implemented
- [ ] Pattern detection working
- [ ] BUILD phase complete

### Thursday (Day 4)
- [ ] Benchmark suite prepared
- [ ] Test binaries collected
- [ ] Performance tests executed

### Friday (Day 5)
- [ ] AI quality validation
- [ ] Metrics collected
- [ ] MEASURE phase complete

---

## Week 6 Full Schedule

### Monday-Tuesday (Days 1-2)
- [ ] Competitive analysis complete
- [ ] Production readiness review
- [ ] ANALYZE phase complete

### Wednesday-Thursday (Days 3-4)
- [ ] CI/CD pipeline configured
- [ ] Release notes written
- [ ] GitHub release prepared

### Friday (Day 5)
- [ ] v1.0 released
- [ ] Community announcements posted
- [ ] GhidrAssist DEPLOY complete ✅

---

## Success Metrics

### Week 5-6 Goals
- [ ] GhidrAssist v1.0 released to GitHub
- [ ] >80% test coverage
- [ ] Analysis time <60s for 1000-function binaries
- [ ] >50 downloads in first week
- [ ] >10 GitHub stars

### Phase 2 Overall Goals (Week 12)
- [ ] 3 plugins released (GhidrAssist, GhidraSimilarity, GhidraGo)
- [ ] >90% test coverage across all plugins
- [ ] CI/CD automates build/test/release
- [ ] Complete documentation + examples
- [ ] Community adoption (>200 total downloads)

---

## Troubleshooting

### "GHIDRA_INSTALL_DIR not set"
```bash
# Windows
set GHIDRA_INSTALL_DIR=C:/Program Files/ghidra_11.0

# Linux/Mac
export GHIDRA_INSTALL_DIR=/opt/ghidra_11.0
```

### "Module not found" in Ghidra
1. Check extraction: Files in `Extensions/Ghidra/GhidrAssist/`
2. Check manifest: `Module.manifest` present
3. Check properties: `extension.properties` valid
4. Restart Ghidra

### "Cannot compile"
```bash
# Verify Java version
java -version  # Should be 17+

# Clean build
gradle clean build
```

### "MCP connection failed"
1. Start MCP server: `python mcp_server.py`
2. Check endpoint in config: `http://localhost:3000`
3. Test manually: `curl http://localhost:3000/health`

---

## Quick Reference Commands

```bash
# Build plugin
gradle build

# Package for distribution
gradle buildExtension

# Run tests
gradle test

# Clean build
gradle clean build

# Install to Ghidra
cp dist/*.zip "C:/Program Files/ghidra_11.0/Extensions/Ghidra/"
```

---

## Phase 2 Progress Tracker

```markdown
## Week 5-6: GhidrAssist
- [ ] Day 1: Plugin structure + MCP client
- [ ] Day 2: Variable renaming
- [ ] Day 3: Vulnerability detection
- [ ] Day 4-5: Performance benchmarking
- [ ] Day 6-7: Competitive analysis
- [ ] Day 8-10: CI/CD + Release

## Week 7-9: GhidraSimilarity
- [ ] Week 7: ML feature extraction
- [ ] Week 8: Model training
- [ ] Week 9: Release v1.0

## Week 10-11: GhidraGo
- [ ] Week 10: Go runtime analysis
- [ ] Week 11: Release v1.0

## Week 12: Integration
- [ ] Integration testing
- [ ] Suite release
- [ ] Community announcement

**Progress:** __ / 24 milestones complete
```

---

## Need Help?

**Detailed Plans:**
- Full Phase 2 Plan: `PHASE2_BMAD_PRODUCTION_ROADMAP.md`
- Consolidated Roadmap: `CONSOLIDATED_EXECUTION_PLAN_2025.md`

**Code Examples:**
- All code snippets in PHASE2_BMAD_PRODUCTION_ROADMAP.md
- Copy-paste ready

**Community:**
- Ghidra Discord
- r/ReverseEngineering
- GitHub Discussions

---

## Next Steps After Week 6

Once GhidrAssist v1.0 is released:

1. **Monitor metrics** (downloads, issues, stars)
2. **Respond to feedback** (<24h response time)
3. **Start GhidraSimilarity** (Week 7)
4. **Plan v1.1** based on community feedback

---

**Ready to Start?**

Open `PHASE2_BMAD_PRODUCTION_ROADMAP.md` and begin:
**Week 5, Day 1, BUILD Phase, Task 1.1**

---

**Last Updated:** October 7, 2025
**Next Review:** Week 6, Day 5 (GhidrAssist release)
**Status:** ✅ READY TO BEGIN
