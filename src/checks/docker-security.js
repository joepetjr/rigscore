import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { calculateCheckScore } from '../scoring.js';

async function readFileSafe(p) {
  try {
    return await fs.promises.readFile(p, 'utf-8');
  } catch {
    return null;
  }
}

const SENSITIVE_MOUNTS = ['/', '/etc', '/root', '/home'];
const COMPOSE_PATTERNS = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'];

export default {
  id: 'docker-security',
  name: 'Docker security',
  category: 'isolation',
  weight: 15,

  async run(context) {
    const { cwd } = context;
    const findings = [];

    // Find compose files
    let composeContent = null;
    let composeFile = null;
    for (const pattern of COMPOSE_PATTERNS) {
      const content = await readFileSafe(path.join(cwd, pattern));
      if (content) {
        composeContent = content;
        composeFile = pattern;
        break;
      }
    }

    // Find Dockerfiles
    const entries = await fs.promises.readdir(cwd).catch(() => []);
    const dockerfiles = entries.filter((e) => e === 'Dockerfile' || e.startsWith('Dockerfile.'));

    if (!composeContent && dockerfiles.length === 0) {
      findings.push({
        severity: 'info',
        title: 'No Docker configuration found',
        detail: 'No docker-compose or Dockerfile found in the project root.',
      });
      return { score: 100, findings };
    }

    // Analyze compose file
    if (composeContent) {
      let compose;
      try {
        compose = YAML.parse(composeContent);
      } catch {
        findings.push({
          severity: 'warning',
          title: `Failed to parse ${composeFile}`,
          detail: 'The compose file has invalid YAML syntax.',
        });
        return { score: calculateCheckScore(findings), findings };
      }

      const services = compose?.services || {};
      for (const [name, service] of Object.entries(services)) {
        // Check privileged
        if (service.privileged === true) {
          findings.push({
            severity: 'critical',
            title: `Container "${name}" running with privileged: true`,
            detail: 'Privileged containers have full access to the host system.',
            remediation: 'Remove privileged: true and use specific capabilities instead.',
            learnMore: 'https://headlessmode.com/blog/docker-isolation',
          });
        }

        // Check network_mode
        if (service.network_mode === 'host') {
          findings.push({
            severity: 'warning',
            title: `Container "${name}" uses host network mode`,
            detail: 'Host network mode exposes all host ports to the container.',
            remediation: 'Use bridge networking with explicit port mappings.',
            learnMore: 'https://headlessmode.com/blog/docker-isolation',
          });
        }

        // Check volumes
        const volumes = service.volumes || [];
        for (const vol of volumes) {
          const volStr = typeof vol === 'string' ? vol : vol.source || '';

          // Docker socket mount
          if (volStr.includes('/var/run/docker.sock')) {
            findings.push({
              severity: 'critical',
              title: `Container "${name}" mounts Docker socket`,
              detail: 'Docker socket access allows container escape and full host control.',
              remediation: 'Remove the Docker socket mount. Use Docker-in-Docker or rootless alternatives.',
              learnMore: 'https://headlessmode.com/blog/docker-socket-risk',
            });
          }

          // Sensitive host mounts
          const hostPath = volStr.split(':')[0];
          for (const sensitive of SENSITIVE_MOUNTS) {
            if (hostPath === sensitive) {
              findings.push({
                severity: 'critical',
                title: `Container "${name}" mounts sensitive path: ${sensitive}`,
                detail: `Mounting ${sensitive} gives the container broad host filesystem access.`,
                remediation: 'Scope volume mounts to specific project directories.',
                learnMore: 'https://headlessmode.com/blog/docker-isolation',
              });
            }
          }
        }
      }
    }

    // Check Dockerfiles for USER directive
    for (const df of dockerfiles) {
      const content = await readFileSafe(path.join(cwd, df));
      if (content && !/^USER\s+/m.test(content)) {
        findings.push({
          severity: 'warning',
          title: `${df} has no USER directive`,
          detail: 'Container will run as root by default.',
          remediation: 'Add a USER directive to run as a non-root user.',
          learnMore: 'https://headlessmode.com/blog/docker-isolation',
        });
      }
    }

    if (findings.length === 0) {
      findings.push({
        severity: 'pass',
        title: 'Docker configuration looks secure',
      });
    }

    return {
      score: calculateCheckScore(findings),
      findings,
    };
  },
};
