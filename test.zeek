# problem: Detect http scan based on 404 response
# tips:
# a global variable to store the relationship of sourceIP to user-agent
# write a event which can return you the http header information
# you may need to study the datatype of Table, Set, String,
# to_lower(str) return a lowercase version string of the original one
# you may use print to output the alert

# 导入sumstats库
@load base/frameworks/sumstats

event zeek_init() {
	# http_responce的数量
	local num1 = SumStats::Reducer($stream = "http_responce", $apply = set(SumStats::SUM));
	# http_responce_404的数量
	local num2 = SumStats::Reducer($stream = "http_responce_404", $apply = set(SumStats::SUM, SumStats::UNIQUE));
	# 照着ppt打的，各个变量的意义还不太明白
	SumStats::create([
		# 作业名称
		$name = "Detect http scan based on 404 responce",
		# 每隔十分钟
		$epoch = 10min,
		$reducers = set(num1, num2),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
			# http_responce的数量（double类型后期用于计算比率，若用整型无法得出结果）
			local numOfResp: double = result["http_responce"]$num;
			# http_responce_404的数量
			local numOf404: double = result["http_responce_404"]$num;
			# http_responce_unique_404的数量
			local numOfUni404: double = result["http_responce_404"]$unique;
			
			# 404的比率
			local ratioOf404: double = numOf404 / numOfResp;
			# unique_404的比率
			local ratioOfUni404: double = numOfUni404 / numOfResp;
			
			# 给定判断条件
			if (numOf404 > 2 && ratioOf404 > 0.2 && ratioOfUni404 > 0.5) {
				print fmt("%s is a scanner with %s scan attempts on %s urls", key$host, result["http_responce_404"]$num, result["http_responce_404"]$unique);
			}
		}
	]);
}


# 照着ppt打的样例，同上还不太明白其语法含义等
event http_reply(c: connection, version: string, code: count, reason: string) {
	if (code == 404) {
		SumStats::observe("http_responce_404",
						SumStats::Key($host = c$id$orig_h),
						SumStats::Observation($str = c$http$uri));
	}
	SumStats::observe("http_responce",
					 SumStats::Key($host = c$id$orig_h),
					 SumStats::Observation($str = c$http$uri));
}
