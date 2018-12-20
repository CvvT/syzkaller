import argparse
import re

import angr

from capstone.x86_const import X86_OP_MEM

class Report:
	'''
	Analyze a kasan report
	'''
	
	# list in order (priority)
	TYPE_NONE   = 0
	TYPE_STORE  = 1
	TYPE_MEMSET = 2
	TYPE_STRCPY = 3
	TYPE_MEMCPY = 4
	
	Name2Type = {
		"strcpy": TYPE_STRCPY,
		"memcpy": TYPE_MEMCPY,
		"memset": TYPE_MEMSET,
	}

	def __init__(self, report, vmlinux):
		self.proj = angr.Project(vmlinux, load_options={"auto_load_libs": False})
		self.report = report
		self.graphs = dict()

	def getType(self, line):
		for k, v in Report.Name2Type.items():
			if k in line:
				return v
		return Report.TYPE_STORE

	def getcause(self, line):
		m = re.search('BUG: KASAN: ([a-z-]+) in (.+) at addr ([a-f0-9]+)', line)
		if m:
			return m.group(1), m.group(2), int(m.group(3), 16)
		return "", "", 0

	def getsize(self, line):
		m = re.search('(Write|Read) of size (\\d+)', line)
		if m:
			return m.group(1), int(m.group(2), 10)
		return "", 0

	def getCalltrace(self, lines):
		trace = list()
		start = False
		for line in lines:
			if line.startswith('Call Trace:'):
				start = True
				continue
			if start:
				if re.search('\\+0x[a-f0-9]+/0x[a-f0-9]+', line):
					trace.append(line)
				else:
					break
		return trace

	def getDetails(self, calltrace, spot):
		# find the deepest function that trigger bug
		index = -1
		for i, call in enumerate(calltrace):
			if spot in call:
				index = i
				break
		if index <= 0:
			raise ValueError("Cannot find the spot")
		asanfunc = ['asan_report', 'check_memory_region']
		for i in range(index, 1, -1):
			if any([each in calltrace[i-1] for each in asanfunc]):
				index = i
				break
		if all([each not in calltrace[index-1] for each in asanfunc]):
			raise ValueError("Cannot find asan report")

		def getAddr(trace):
			m = re.search('\\[\\<([a-f0-9]+)>\\]', trace)
			if m: return int(m.group(1), 16)
			return 0

		def getsymbol(trace):
			m = re.search('\\[\\<[a-f0-9]+>\\]\\s(.+)\\+0x[a-f0-9]+/0x[a-f0-9]+', trace)
			if m: return m.group(1)
			return ""

		# find the appropriate function to analyze
		tgtfunc = ['memcpy', 'memset', 'strcpy']
		funCall = False
		retType = Report.TYPE_STORE
		if any([each in calltrace[index] for each in tgtfunc]):
			retType = self.getType(getsymbol(calltrace[index]))
			index += 1
			funCall = True

		addr = getAddr(calltrace[index])
		name = getsymbol(calltrace[index])
		symbol = self.proj.loader.find_symbol(name)
		print('target %s addr 0x%x' % (name, addr))
		if not symbol:
			raise ValueError("Cannot find symbol %s" % name)

		if name not in self.graphs:
			cfg = self.proj.analyses.CFGEmulated(context_sensitivity_level=0, starts=[symbol.rebased_addr], 
				call_depth=0, normalize=True)
			func = cfg.functions[symbol.rebased_addr]
			if func is None:
				raise ValueError("Construct cfg failed")
			self.graphs[name] = func.transition_graph
		graph = self.graphs[name]

		def get_node(nodes, addr):
			for node in nodes:
				if node.addr == addr:
					return node
			return None

		target = None
		target_node = get_node(graph.nodes, addr)
		
		if funCall:
			# should we just use the following heuristic
			# the size of instruction CALL is 5 in x86 64
			# target = addr - 5
			target_node = get_node(graph.nodes, addr)
			preds = [x for x in graph.predecessors(target_node) if x.size is not None]
			if len(preds) != 1:
				raise ValueError("Multiple predecessors")
			pred = self.proj.factory.block(preds[0].addr)
			target = pred.instruction_addrs[-1]
		else:
			def get_next(graph, node):
				succs = [x for x in graph.successors(node) if x.size is not None]
				if len(succs) != 1:
					raise ValueError("Multiple successors")
				return succs[0]

			block = self.proj.factory.block(target_node.addr)
			count = 3
			while count > 0:
				for cs_insn in block.capstone.insns:
					if len(cs_insn.operands) == 2:
						# Assume x86
						if cs_insn.operands[0].type == X86_OP_MEM:
							target = cs_insn.address
							break
				if target is not None:
					break
				target_node = get_next(graph, target_node)
				block = self.proj.factory.block(target_node.addr)
				count -= 1
		print("Target address: 0x%x" % target)
		return target, retType
		
	def pickCandidate(self, candidates):
		retAddr, retType, retsize = 0, Report.TYPE_NONE, 0
		for addr, typ, size in candidates:
			if typ > retType:
				retAddr, retType, retsize = addr, typ, size
				continue
			if typ == retType and size > retsize:
				retAddr, retsize = addr, size
		return retAddr, retType, retsize

	def getReports(self):
		results = list()
		with open(self.report, "r") as f:
			content = ''.join(f.readlines())
			blocks = content.split("==================================================================")[1:]
			spots = list()
			for block in blocks:
				lines = block.split("\n")
				if len(lines) < 5:
					continue
				cause, spot, addr = self.getcause(lines[1])
				if spot in spots:
					continue
				spots.append(spot)
				op, size = self.getsize(lines[2])
				if op == "Read":
					continue
				calltrace = self.getCalltrace(lines)
				print("%s %s at 0x%x with %d" % (cause, spot, addr, size))
				print('Call Trace: \n%s' % '\n'.join(calltrace))
				addr, typ = self.getDetails(calltrace, spot)
				results.append((addr, typ, size))
		print("All candidates:")
		for addr, typ, size in results:
			print("Addr: 0x%x, Type: %d, Size: %d" % (addr, typ, size))
		addr, typ, size = self.pickCandidate(results)
		print("Promising candidate: Addr: 0x%x, Type: %d, Size: %d" 
			% (addr, typ, size))
	
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('report', help='path to the report file')
	parser.add_argument('vmlinux', help='path to the vmlinux binary')
	args = parser.parse_args()
	rep = Report(args.report, args.vmlinux)
	rep.getReports()
