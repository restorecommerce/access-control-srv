import * as _ from 'lodash';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { AccessController } from './accessController';
import * as interfaces from './interfaces';

export const formatTarget = (target: any) => {
  if (!target) {
    return null;
  }

  return {
    subject: target.subject ? target.subject : [],
    resources: target.resources ? target.resources : [],
    action: target.action ? target.action : []
  };
};

const loadPolicies = (document: any, accessController: AccessController) => {
  const policySets = document.policy_sets;

  for (let policySetYaml of policySets) {

    let policies = new Map<string, interfaces.Policy>();
    for (let policyYaml of policySetYaml.policies) {

      let rules = new Map<string, interfaces.Rule>();
      if (policyYaml.rules) {
        for (let ruleYaml of policyYaml.rules) {
          const ruleID = ruleYaml.id;
          const ruleName = ruleYaml.name;
          const ruleDescription: string = ruleYaml.description;
          const ruleTarget = formatTarget(ruleYaml.target);

          const effect: interfaces.Effect = ruleYaml.effect;
          const contextQuery = ruleYaml.context_query;  // may be null
          const condition = ruleYaml.condition; // JS code; may be null

          const rule: interfaces.Rule = {
            id: ruleID,
            name: ruleName,
            description: ruleDescription,
            target: ruleTarget,
            effect,
            contextQuery,
            condition
          };
          rules.set(rule.id, rule);
        }
      }

      const policyID = policyYaml.id;
      const policyName = policyYaml.name;
      const policyDescription = policyYaml.description;
      const policyCA = policyYaml.combining_algorithm;
      const policyEffect = policyYaml.effect;
      const policyTarget = formatTarget(policyYaml.target);

      const policy: interfaces.Policy = {
        id: policyID,
        name: policyName,
        description: policyDescription,
        combiningAlgorithm: policyCA,
        combinables: rules,
        effect: policyEffect,
        target: policyTarget
      };
      policies.set(policy.id, policy);
    }

    const policySet: interfaces.PolicySet = {
      id: policySetYaml.id,
      name: policySetYaml.name,
      description: policySetYaml.description,
      combiningAlgorithm: policySetYaml.combining_algorithm,
      combinables: policies,
      target: formatTarget(policySetYaml.target)
    };

    accessController.updatePolicySet(policySet);
  }

  return accessController;
};

export const loadPoliciesFromDoc = async (accessController: AccessController, filepath: string) => {
  if (_.isNil(filepath)) {
    throw new Error('No filepath specified for policies document');
  }

  if (_.isNil(accessController)) {
    throw new Error('No filepath specified for policies document');
  }

  return new Promise<AccessController>((resolve, reject) => {
    fs.exists(filepath, (exists) => {
      if (!exists) {
        reject(`Policies file ${filepath} does not exist`);
      }

      fs.readFile(filepath, (err, data) => {
        const document = yaml.safeLoad(data, 'utf8');
        loadPolicies(document, accessController);
        resolve(accessController);
      });
    });
  });
};
