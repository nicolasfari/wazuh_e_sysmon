# wazuh_e_sysmon
# SOC Investigation: Monday Monitor (Wazuh & Sysmon) TryHackMe
<img width="1911" height="947" alt="wazuh" src="https://github.com/user-attachments/assets/da24a47f-e129-4b46-a2f4-74cec08890ad" />


## 📋 Resumo do Caso
Análise de incidentes realizada para a fintech **Swiftspend Finance**. O objetivo foi avaliar a eficácia do monitoramento de endpoints (**Wazuh** + **Sysmon**) frente a simulações de ataques.

## Ferramentas Utilizadas
* **Wazuh (SIEM/XDR):** Centralização e análise de logs.
* **Sysmon:** Monitoramento avançado de processos, rede e arquivos.
* **Atomic Red Team:** Framework de simulação de adversários identificado durante a análise.

---

## Investigação e Artefatos (Digital Forensics)

### 1. Vetor de Acesso Inicial
* **Pergunta:** Qual é o nome do arquivo de acesso inicial salvo no host?
* **Resposta:** `SwiftSpend_Financial_Expenses.xlsm`
* **Análise:** O ataque iniciou via técnica de **Phishing (T1566)**. O arquivo é uma planilha Excel habilitada para macros que, ao ser executada, deu início à cadeia de infecção no host.
  <img width="1896" height="957" alt="arquivobaixado" src="https://github.com/user-attachments/assets/3d8f54f2-b6bd-4e53-bcda-430392dbc8f6" />

---
### 2. Persistência e Evasão de Defesa
* **Pergunta:** Qual é o comando completo executado para criar uma tarefa agendada?
* **Resposta:** ```bash
  "cmd.exe" /c "reg add HKCU\SOFTWARE\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0= /f & schtasks.exe /Create /F /TN "ATOMIC-T1053.005" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 12:34"
* **Análise:** O adversário utilizou uma técnica de Living-off-the-Land (LotL). Primeiro, injetou um payload Base64 no Registro do Windows (reg add) e depois criou uma tarefa agendada (schtasks) para executar esse payload via PowerShell, evadindo detecções baseadas apenas em arquivos.
<img width="1909" height="944" alt="tarefaagendada_e_hora" src="https://github.com/user-attachments/assets/4cc65804-34bb-4196-82b3-3de94a396a37" />

---

### 3. Agendamento (Persistence)
* **Pergunta:** A que horas a tarefa agendada deve ser executada?  
* **Resposta:** `12:34`  
* **Análise:** Identificado através do parâmetro `/st` (Start Time) no log de criação do processo do Sysmon. Isso indica que o atacante configurou uma tarefa agendada para manter persistência no sistema.

---

### 4. Ofuscação (Deobfuscation)
* **Pergunta:** O que foi codificado no payload?  
* **Resposta:** cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0= | decodificando > ping www.youarevulnerable.thm 
* **Análise:** A string em Base64 extraída do registro foi decodificada, revelando um comando de beaconing para testar conectividade com domínio controlado pelo atacante.
<img width="1315" height="708" alt="decodificado" src="https://github.com/user-attachments/assets/3de46d23-e615-4d9c-a02c-bfecbca537ae" />
<img width="1909" height="944" alt="codificado" src="https://github.com/user-attachments/assets/d5c2e979-31a6-4dc8-b5ac-5a8eaf3616b6" />

---

### 5. Gestão de Contas (Persistence)
* **Pergunta:** Qual foi a senha definida para a nova conta de usuário?  
* **Resposta:** `I_AM_M0NIT0R1NG`  
* **Análise:** Detectada através da execução do `net.exe`. O atacante criou uma nova conta local para manter acesso persistente ao sistema.
<img width="1890" height="965" alt="senha" src="https://github.com/user-attachments/assets/1baaae08-6d85-4206-bee2-a95a094923a9" />

---

### 6. Acesso a Credenciais (Credential Access)
* **Pergunta:** Qual o nome do arquivo `.exe` usado para extrair as credenciais?  
* **Resposta:** `memotech.exe`  
* **Análise:** Binário associado ao Mimikatz renomeado para evasão. Utilizado para dump de memória do `lsass.exe` e extração de credenciais.

---

### 7. Exfiltração de Dados
* **Pergunta:** Qual era a flag que fazia parte dos dados exfiltrados?  
* **Resposta:** `THM{M0N1T0R_1$_1N_3FF3CT}`  
* **Análise:** Identificada durante análise do tráfego de exfiltração, indicando vazamento de dados sensíveis.
<img width="1907" height="949" alt="credenciais" src="https://github.com/user-attachments/assets/5868339e-5a03-4981-bc6e-7f8966176648" />

---

### 🛠️ Técnicas MITRE ATT&CK Mapeadas

| Tática             | Técnica                  | ID         |
|------------------|------------------------|------------|
| Initial Access    | Phishing: Malicious File | T1566.001  |
| Persistence       | Scheduled Task           | T1053.005  |
| Defense Evasion   | Modify Registry          | T1112      |
| Credential Access | OS Credential Dumping    | T1003.001  |
---

## 🚀 Conclusão
A investigação demonstrou o uso de técnicas de "Living off the Land" (LotL), como o uso de ferramentas nativas do Windows (`reg.exe`, `schtasks.exe`, `powershell.exe`) para mascarar atividades maliciosas. O monitoramento de chaves de registro e execuções de PowerShell encodado foram cruciais para a detecção.
