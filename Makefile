
help: ## Show available commands
	@printf "$(COLOR_BLUE)Available commands:$(COLOR_RESET)\n"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "%s\t%s\n", $$1, $$2}' $(MAKEFILE_LIST) \
					| sort \
					| awk -F"\t" -v green="$(COLOR_GREEN)" -v blue="$(COLOR_BLUE)" -v reset="$(COLOR_RESET)" 'function line(prefix){printf "%s-------------------------------- %s --------------------------------%s\n", blue, prefix, reset} function order(p){return (p=="misc"?0:(p=="dev"?1:(p=="local"?2:(p=="test"?3:(p=="prod"?4:99)))))} {cmd=$$1; desc=$$2; prefix=cmd; if(index(cmd,"-")>0){sub(/-.*/,"",prefix)} else {prefix="misc"}; groups[prefix]=groups[prefix] sprintf("%s%-24s%s %s\n", green, cmd, reset, desc)} END{n=0; for(p in groups){keys[n++]=p}; for(i=0;i<n;i++){for(j=i+1;j<n;j++){if(order(keys[j])<order(keys[i]) || (order(keys[j])==order(keys[i]) && keys[j]<keys[i])){t=keys[i];keys[i]=keys[j];keys[j]=t}}}; for(i=0;i<n;i++){p=keys[i]; line(p); printf "%s", groups[p]}}'
	@echo
	@echo "Tip: use 'make <target>' (e.g. 'make dev-up')"

test: ## Run tests
	cargo test; \
	cargo test --features actix-web
