/**
 * BPMN 2.0 Process Orchestrator & OMG XML Generator for Solana Anchor DevSecOps
 * Supports visual workflow diagramming and standards-compliant OMG BPMN 2.0 XML export
 */

export interface BpmnTask {
  id: string;
  name: string;
  type: 'startEvent' | 'userTask' | 'serviceTask' | 'exclusiveGateway' | 'endEvent';
  assignee?: string;
  status: 'COMPLETED' | 'IN_PROGRESS' | 'PENDING' | 'PASSED';
  description: string;
}

export const ANCHOR_DEVSECOPS_BPMN_TASKS: BpmnTask[] = [
  { id: 'start_1', name: 'Início do Ciclo DevSecOps', type: 'startEvent', status: 'COMPLETED', description: 'Gatilho de auditoria disparado no repositório' },
  { id: 'task_code', name: 'Edição de Contrato Rust/Anchor', type: 'userTask', assignee: 'Developer', status: 'COMPLETED', description: 'Desenvolvimento com macros seguras e PDA' },
  { id: 'task_ast', name: 'Auditoria Estática de AST', type: 'serviceTask', assignee: 'AST Engine', status: 'COMPLETED', description: 'Inspeção de signers, has_one e 49B de memória' },
  { id: 'gw_ast_eval', name: 'Score AST >= 85?', type: 'exclusiveGateway', status: 'PASSED', description: 'Portão condicional de qualidade de código' },
  { id: 'task_fuzz', name: 'Fuzzing de 10.000 Vetores', type: 'serviceTask', assignee: 'SVM Fuzzer', status: 'COMPLETED', description: 'Testes de u64::MAX, underflow e invariantes' },
  { id: 'gw_fuzz_eval', name: 'Violações == 0?', type: 'exclusiveGateway', status: 'PASSED', description: 'Verificação de integridade de invariantes' },
  { id: 'task_graphrag', name: 'Análise GraphRAG & Grafo de Ataque', type: 'serviceTask', assignee: 'Gemini AI', status: 'COMPLETED', description: 'Mapeamento de vetores de exploração cross-instruction' },
  { id: 'task_pr', name: 'Geração de Commit e Pull Request Atómico', type: 'serviceTask', assignee: 'GitHub Pipeline', status: 'COMPLETED', description: 'Abertura de PR com checklist de segurança aprovado' },
  { id: 'end_1', name: 'Contrato Verificado & Pronto para Deploy', type: 'endEvent', status: 'COMPLETED', description: 'Entrega contínua certificada no Devnet' },
];

/**
 * Generates official OMG BPMN 2.0 XML string
 */
export function generateOmgBpmnXml(processId: string = 'SolanaAnchorDevSecOpsProcess'): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL" 
                  xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI" 
                  xmlns:dc="http://www.omg.org/spec/DD/20100524/DC" 
                  xmlns:di="http://www.omg.org/spec/DD/20100524/DI" 
                  xmlns:camunda="http://camunda.org/schema/1.0/bpmn" 
                  id="Definitions_AnchorDevSecOps" 
                  targetNamespace="http://bpmn.io/schema/bpmn" 
                  exporter="Solana Anchor DevSecOps IDE" 
                  exporterVersion="1.0.0">
  <bpmn:process id="${processId}" name="Solana Anchor DevSecOps Security Pipeline" isExecutable="true">
    <bpmn:startEvent id="start_1" name="Trigger DevSecOps Audit">
      <bpmn:outgoing>flow_1</bpmn:outgoing>
    </bpmn:startEvent>
    <bpmn:userTask id="task_code" name="Write Anchor Program (lib.rs)" camunda:assignee="Developer">
      <bpmn:incoming>flow_1</bpmn:incoming>
      <bpmn:outgoing>flow_2</bpmn:outgoing>
    </bpmn:userTask>
    <bpmn:serviceTask id="task_ast" name="AST Static Security Auditor" camunda:class="com.solana.ast.Auditor">
      <bpmn:incoming>flow_2</bpmn:incoming>
      <bpmn:outgoing>flow_3</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:exclusiveGateway id="gw_ast_eval" name="AST Score &gt;= 85?">
      <bpmn:incoming>flow_3</bpmn:incoming>
      <bpmn:outgoing>flow_4_pass</bpmn:outgoing>
    </bpmn:exclusiveGateway>
    <bpmn:serviceTask id="task_fuzz" name="SVM Property Fuzzing (10,000 Vectors)" camunda:class="com.solana.fuzzer.Engine">
      <bpmn:incoming>flow_4_pass</bpmn:incoming>
      <bpmn:outgoing>flow_5</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:exclusiveGateway id="gw_fuzz_eval" name="Invariant Violations == 0?">
      <bpmn:incoming>flow_5</bpmn:incoming>
      <bpmn:outgoing>flow_6_pass</bpmn:outgoing>
    </bpmn:exclusiveGateway>
    <bpmn:serviceTask id="task_graphrag" name="GraphRAG Cross-Instruction Audit" camunda:class="com.solana.graphrag.Auditor">
      <bpmn:incoming>flow_6_pass</bpmn:incoming>
      <bpmn:outgoing>flow_7</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:serviceTask id="task_pr" name="Atomic GitHub Commit &amp; PR Dispatch" camunda:class="com.solana.github.Pipeline">
      <bpmn:incoming>flow_7</bpmn:incoming>
      <bpmn:outgoing>flow_8</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:endEvent id="end_1" name="Deployment Certified">
      <bpmn:incoming>flow_8</bpmn:incoming>
    </bpmn:endEvent>
    
    <bpmn:sequenceFlow id="flow_1" sourceRef="start_1" targetRef="task_code" />
    <bpmn:sequenceFlow id="flow_2" sourceRef="task_code" targetRef="task_ast" />
    <bpmn:sequenceFlow id="flow_3" sourceRef="task_ast" targetRef="gw_ast_eval" />
    <bpmn:sequenceFlow id="flow_4_pass" name="Passed" sourceRef="gw_ast_eval" targetRef="task_fuzz" />
    <bpmn:sequenceFlow id="flow_5" sourceRef="task_fuzz" targetRef="gw_fuzz_eval" />
    <bpmn:sequenceFlow id="flow_6_pass" name="Verified" sourceRef="gw_fuzz_eval" targetRef="task_graphrag" />
    <bpmn:sequenceFlow id="flow_7" sourceRef="task_graphrag" targetRef="task_pr" />
    <bpmn:sequenceFlow id="flow_8" sourceRef="task_pr" targetRef="end_1" />
  </bpmn:process>
  <bpmndi:BPMNDiagram id="BPMNDiagram_1">
    <bpmndi:BPMNPlane id="BPMNPlane_1" bpmnElement="${processId}">
      <bpmndi:BPMNShape id="_BPMNShape_StartEvent_2" bpmnElement="start_1">
        <dc:Bounds x="160" y="100" width="36" height="36" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Activity_Code_di" bpmnElement="task_code">
        <dc:Bounds x="250" y="78" width="100" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Activity_Ast_di" bpmnElement="task_ast">
        <dc:Bounds x="400" y="78" width="100" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Gateway_Ast_di" bpmnElement="gw_ast_eval" isMarkerVisible="true">
        <dc:Bounds x="550" y="93" width="50" height="50" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Activity_Fuzz_di" bpmnElement="task_fuzz">
        <dc:Bounds x="650" y="78" width="100" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Gateway_Fuzz_di" bpmnElement="gw_fuzz_eval" isMarkerVisible="true">
        <dc:Bounds x="800" y="93" width="50" height="50" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Activity_GraphRag_di" bpmnElement="task_graphrag">
        <dc:Bounds x="900" y="78" width="100" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Activity_PR_di" bpmnElement="task_pr">
        <dc:Bounds x="1050" y="78" width="100" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Event_End_di" bpmnElement="end_1">
        <dc:Bounds x="1200" y="100" width="36" height="36" />
      </bpmndi:BPMNShape>
    </bpmndi:BPMNPlane>
  </bpmndi:BPMNDiagram>
</bpmn:definitions>`;
}

/**
 * Triggers a download of the OMG BPMN 2.0 XML file in the browser
 */
export function downloadBpmnFile(filename: string = 'solana-anchor-devsecops-workflow.bpmn') {
  const xml = generateOmgBpmnXml();
  const blob = new Blob([xml], { type: 'application/xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
