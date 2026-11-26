/**
 * BPMN 2.0 model of the implemented EGC one-click flow.
 */

export interface BpmnTask {
  id: string;
  name: string;
  type: 'startEvent' | 'userTask' | 'serviceTask' | 'exclusiveGateway' | 'endEvent';
  assignee?: string;
  status: 'NOT_EXECUTED';
  description: string;
}

export const ANCHOR_DEVSECOPS_BPMN_TASKS: BpmnTask[] = [
  {
    id: 'start_1',
    name: 'Início da solicitação EGC',
    type: 'startEvent',
    status: 'NOT_EXECUTED',
    description: 'Recebe o comando e os parâmetros fornecidos pelo adaptador de transporte.',
  },
  {
    id: 'task_input',
    name: 'Informar repositório e credencial GitHub',
    type: 'userTask',
    assignee: 'Caller',
    status: 'NOT_EXECUTED',
    description: 'Fornece owner, repoName e PAT; a credencial não faz parte das respostas do contrato.',
  },
  {
    id: 'task_validate',
    name: 'Validar parâmetros e isolamento do alvo',
    type: 'serviceTask',
    assignee: 'EGC Command Center',
    status: 'NOT_EXECUTED',
    description: 'Valida owner/repo antes de registrar sessão ou iniciar a varredura.',
  },
  {
    id: 'gw_target_valid',
    name: 'Parâmetros válidos?',
    type: 'exclusiveGateway',
    status: 'NOT_EXECUTED',
    description: 'Alvos inválidos encerram o fluxo com erro antes de qualquer chamada ao GitHub.',
  },
  {
    id: 'task_scan',
    name: 'Executar scan AST e contexto arquitetural',
    type: 'serviceTask',
    assignee: 'Repository Scanner / GraphRAG / DDD',
    status: 'NOT_EXECUTED',
    description: 'Inspeciona arquivos disponíveis e produz findings, resumo de scan e contexto.',
  },
  {
    id: 'task_issues',
    name: 'Criar issues no GitHub',
    type: 'serviceTask',
    assignee: 'GitHub Issues API',
    status: 'NOT_EXECUTED',
    description: 'Registra resultados e acumula falhas; a falha não impede a tentativa de PR.',
  },
  {
    id: 'task_pr',
    name: 'Criar Pull Request com merge manual',
    type: 'serviceTask',
    assignee: 'GitHub PR Service',
    status: 'NOT_EXECUTED',
    description: 'Envia os arquivos selecionados e abre PR sem ativar auto-merge.',
  },
  {
    id: 'gw_pr_success',
    name: 'Pull Request criado?',
    type: 'exclusiveGateway',
    status: 'NOT_EXECUTED',
    description: 'Somente o sucesso do PR aciona a limpeza imediata do estado EGC.',
  },
  {
    id: 'task_cleanup',
    name: 'Limpar estado após PR criado',
    type: 'serviceTask',
    assignee: 'EGC State Manager',
    status: 'NOT_EXECUTED',
    description: 'Executa purge do estado local depois de confirmar a criação do PR.',
  },
  {
    id: 'task_pdf',
    name: 'Gerar relatório PDF auditável',
    type: 'serviceTask',
    assignee: 'PDF Report Service',
    status: 'NOT_EXECUTED',
    description: 'Gera evidência a partir do scan, issues e resultado do PR; falhas são acumuladas.',
  },
  {
    id: 'end_success',
    name: 'Devolver resultado e evidências',
    type: 'endEvent',
    status: 'NOT_EXECUTED',
    description: 'Retorna resultados, erros, nome do PDF e estado de limpeza.',
  },
  {
    id: 'end_invalid',
    name: 'Encerrar por parâmetros inválidos',
    type: 'endEvent',
    status: 'NOT_EXECUTED',
    description: 'Retorna erro de validação sem executar scan, chamadas externas ou PDF.',
  },
];

export function generateOmgBpmnXml(processId = 'EgcOneClickProcess'): string {
  if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(processId)) {
    throw new Error('processId must be a valid BPMN identifier.');
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
                  xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI"
                  xmlns:dc="http://www.omg.org/spec/DD/20100524/DC"
                  xmlns:di="http://www.omg.org/spec/DD/20100524/DI"
                  xmlns:camunda="http://camunda.org/schema/1.0/bpmn"
                  id="Definitions_EgcOneClick"
                  targetNamespace="https://egc.devsecops/contracts/v1"
                  exporter="EGC DevSecOps IDE"
                  exporterVersion="1.0.0">
  <bpmn:process id="${processId}" name="EGC One-Click: Entrada, Validação, Execução, Evidência e Auditoria" isExecutable="false">
    <bpmn:startEvent id="start_1" name="Solicitação recebida">
      <bpmn:outgoing>flow_1</bpmn:outgoing>
    </bpmn:startEvent>
    <bpmn:userTask id="task_input" name="Informar repositório e credencial GitHub">
      <bpmn:incoming>flow_1</bpmn:incoming>
      <bpmn:outgoing>flow_2</bpmn:outgoing>
    </bpmn:userTask>
    <bpmn:serviceTask id="task_validate" name="Validar parâmetros e isolamento do alvo" camunda:class="EGC.validateTargetIsolation">
      <bpmn:incoming>flow_2</bpmn:incoming>
      <bpmn:outgoing>flow_3</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:exclusiveGateway id="gw_target_valid" name="Parâmetros válidos?">
      <bpmn:incoming>flow_3</bpmn:incoming>
      <bpmn:outgoing>flow_target_valid</bpmn:outgoing>
      <bpmn:outgoing>flow_target_invalid</bpmn:outgoing>
    </bpmn:exclusiveGateway>
    <bpmn:endEvent id="end_invalid" name="Erro de validação">
      <bpmn:incoming>flow_target_invalid</bpmn:incoming>
    </bpmn:endEvent>
    <bpmn:serviceTask id="task_scan" name="Scan AST e contexto arquitetural" camunda:class="EGC.scanAndBuildContext">
      <bpmn:incoming>flow_target_valid</bpmn:incoming>
      <bpmn:outgoing>flow_4</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:serviceTask id="task_issues" name="Criar issues; acumular falhas e continuar" camunda:class="EGC.createGitHubIssues">
      <bpmn:incoming>flow_4</bpmn:incoming>
      <bpmn:outgoing>flow_5</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:serviceTask id="task_pr" name="Criar Pull Request sem auto-merge" camunda:class="EGC.createGitHubPullRequest">
      <bpmn:incoming>flow_5</bpmn:incoming>
      <bpmn:outgoing>flow_6</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:exclusiveGateway id="gw_pr_success" name="Pull Request criado?">
      <bpmn:incoming>flow_6</bpmn:incoming>
      <bpmn:outgoing>flow_pr_created</bpmn:outgoing>
      <bpmn:outgoing>flow_pr_failed</bpmn:outgoing>
    </bpmn:exclusiveGateway>
    <bpmn:serviceTask id="task_cleanup" name="Limpar estado após PR criado" camunda:class="EGC.purgeEgcState">
      <bpmn:incoming>flow_pr_created</bpmn:incoming>
      <bpmn:outgoing>flow_7</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:serviceTask id="task_pdf" name="Gerar relatório PDF auditável" camunda:class="EGC.generateAuditablePdfReport">
      <bpmn:incoming>flow_7</bpmn:incoming>
      <bpmn:incoming>flow_pr_failed</bpmn:incoming>
      <bpmn:outgoing>flow_8</bpmn:outgoing>
    </bpmn:serviceTask>
    <bpmn:endEvent id="end_success" name="Resultado e evidências devolvidos">
      <bpmn:incoming>flow_8</bpmn:incoming>
    </bpmn:endEvent>
    <bpmn:sequenceFlow id="flow_1" sourceRef="start_1" targetRef="task_input" />
    <bpmn:sequenceFlow id="flow_2" sourceRef="task_input" targetRef="task_validate" />
    <bpmn:sequenceFlow id="flow_3" sourceRef="task_validate" targetRef="gw_target_valid" />
    <bpmn:sequenceFlow id="flow_target_valid" name="Válidos" sourceRef="gw_target_valid" targetRef="task_scan" />
    <bpmn:sequenceFlow id="flow_target_invalid" name="Inválidos" sourceRef="gw_target_valid" targetRef="end_invalid" />
    <bpmn:sequenceFlow id="flow_4" sourceRef="task_scan" targetRef="task_issues" />
    <bpmn:sequenceFlow id="flow_5" sourceRef="task_issues" targetRef="task_pr" />
    <bpmn:sequenceFlow id="flow_6" sourceRef="task_pr" targetRef="gw_pr_success" />
    <bpmn:sequenceFlow id="flow_pr_created" name="Criado: limpar estado" sourceRef="gw_pr_success" targetRef="task_cleanup" />
    <bpmn:sequenceFlow id="flow_pr_failed" name="Falhou: preservar erro e continuar" sourceRef="gw_pr_success" targetRef="task_pdf" />
    <bpmn:sequenceFlow id="flow_7" sourceRef="task_cleanup" targetRef="task_pdf" />
    <bpmn:sequenceFlow id="flow_8" sourceRef="task_pdf" targetRef="end_success" />
  </bpmn:process>
  <bpmndi:BPMNDiagram id="BPMNDiagram_EgcOneClick">
    <bpmndi:BPMNPlane id="BPMNPlane_EgcOneClick" bpmnElement="${processId}">
      <bpmndi:BPMNShape id="Shape_start_1" bpmnElement="start_1">
        <dc:Bounds x="100" y="180" width="36" height="36" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_input" bpmnElement="task_input">
        <dc:Bounds x="180" y="158" width="130" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_validate" bpmnElement="task_validate">
        <dc:Bounds x="340" y="158" width="160" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_gw_target_valid" bpmnElement="gw_target_valid" isMarkerVisible="true">
        <dc:Bounds x="530" y="172" width="56" height="56" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_end_invalid" bpmnElement="end_invalid">
        <dc:Bounds x="570" y="330" width="36" height="36" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_scan" bpmnElement="task_scan">
        <dc:Bounds x="620" y="158" width="150" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_issues" bpmnElement="task_issues">
        <dc:Bounds x="810" y="158" width="160" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_pr" bpmnElement="task_pr">
        <dc:Bounds x="1010" y="158" width="150" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_gw_pr_success" bpmnElement="gw_pr_success" isMarkerVisible="true">
        <dc:Bounds x="1180" y="172" width="56" height="56" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_cleanup" bpmnElement="task_cleanup">
        <dc:Bounds x="1280" y="80" width="160" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_task_pdf" bpmnElement="task_pdf">
        <dc:Bounds x="1490" y="158" width="160" height="80" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNShape id="Shape_end_success" bpmnElement="end_success">
        <dc:Bounds x="1700" y="180" width="36" height="36" />
      </bpmndi:BPMNShape>
      <bpmndi:BPMNEdge id="Edge_flow_1" bpmnElement="flow_1">
        <di:waypoint x="136" y="198" />
        <di:waypoint x="180" y="198" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_2" bpmnElement="flow_2">
        <di:waypoint x="310" y="198" />
        <di:waypoint x="340" y="198" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_3" bpmnElement="flow_3">
        <di:waypoint x="500" y="198" />
        <di:waypoint x="530" y="200" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_target_valid" bpmnElement="flow_target_valid">
        <di:waypoint x="586" y="200" />
        <di:waypoint x="620" y="198" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_target_invalid" bpmnElement="flow_target_invalid">
        <di:waypoint x="558" y="228" />
        <di:waypoint x="558" y="285" />
        <di:waypoint x="588" y="330" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_4" bpmnElement="flow_4">
        <di:waypoint x="770" y="198" />
        <di:waypoint x="810" y="198" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_5" bpmnElement="flow_5">
        <di:waypoint x="970" y="198" />
        <di:waypoint x="1010" y="198" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_6" bpmnElement="flow_6">
        <di:waypoint x="1160" y="198" />
        <di:waypoint x="1180" y="200" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_pr_created" bpmnElement="flow_pr_created">
        <di:waypoint x="1208" y="172" />
        <di:waypoint x="1245" y="120" />
        <di:waypoint x="1280" y="120" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_pr_failed" bpmnElement="flow_pr_failed">
        <di:waypoint x="1208" y="228" />
        <di:waypoint x="1280" y="270" />
        <di:waypoint x="1460" y="270" />
        <di:waypoint x="1490" y="198" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_7" bpmnElement="flow_7">
        <di:waypoint x="1440" y="120" />
        <di:waypoint x="1460" y="120" />
        <di:waypoint x="1490" y="180" />
      </bpmndi:BPMNEdge>
      <bpmndi:BPMNEdge id="Edge_flow_8" bpmnElement="flow_8">
        <di:waypoint x="1650" y="198" />
        <di:waypoint x="1700" y="198" />
      </bpmndi:BPMNEdge>
    </bpmndi:BPMNPlane>
  </bpmndi:BPMNDiagram>
</bpmn:definitions>`;
}

export function downloadBpmnFile(filename = 'egc-one-click-workflow.bpmn') {
  const xml = generateOmgBpmnXml();
  const blob = new Blob([xml], { type: 'application/xml' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
