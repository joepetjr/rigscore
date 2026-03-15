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
    const { cwd, config } = context;
    const findings = [];

    // Collect compose file paths: defaults + config-specified
    const composeCandidates = COMPOSE_PATTERNS.map((p) => path.join(cwd, p));
    if (config?.paths?.dockerCompose) {
      for (const p of config.paths.dockerCompose) {
        composeCandidates.push(p);
      }
    }

    // Find first compose file
    let composeContent = null;
    let composeFile = null;
    for (const candidate of composeCandidates) {
      const content = await readFileSafe(candidate);
      if (content) {
        composeContent = content;
        composeFile = path.basename(candidate);
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

        // Check cap_drop
        const capDrop = service.cap_drop || [];
        if (!capDrop.includes('ALL')) {
          findings.push({
            severity: 'warning',
            title: `Container "${name}" missing cap_drop: [ALL]`,
            detail: 'Without dropping all capabilities, the container retains default Linux capabilities.',
            remediation: 'Add cap_drop: [ALL] and only add back specific capabilities needed.',
            learnMore: 'https://headlessmode.com/blog/docker-isolation',
          });
        }

        // Check security_opt for no-new-privileges
        const securityOpt = service.security_opt || [];
        if (!securityOpt.includes('no-new-privileges')) {
          findings.push({
            severity: 'info',
            title: `Container "${name}" missing no-new-privileges`,
            detail: 'Without no-new-privileges, processes inside the container can escalate privileges.',
            remediation: 'Add security_opt: [no-new-privileges] to the service.',
          });
        }

        // Check for user directive
        if (!service.user) {
          findings.push({
            severity: 'warning',
            title: `Container "${name}" has no user directive`,
            detail: 'Container will run as root by default.',
            remediation: 'Add a user directive to run as a non-root user.',
            learnMore: 'https://headlessmode.com/blog/docker-isolation',
          });
        }

        // Check memory limits
        const hasMemLimit = service.mem_limit ||
          service.deploy?.resources?.limits?.memory;
        if (!hasMemLimit) {
          findings.push({
            severity: 'info',
            title: `Container "${name}" has no memory limit`,
            detail: 'Without memory limits, a runaway container can exhaust host memory.',
            remediation: 'Add mem_limit or deploy.resources.limits.memory to the service.',
          });
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
