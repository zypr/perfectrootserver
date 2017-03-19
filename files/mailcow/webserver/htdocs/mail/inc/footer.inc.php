<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.5/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-material-design/0.3.0/js/ripples.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-material-design/0.3.0/js/material.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-select/1.7.5/js/bootstrap-select.js"></script>

<script>
$(document).ready(function() {
	$('select').selectpicker();
});
var toValidate = $('#imap_host, #imap_username, #imap_password'),
valid = false;
toValidate.keyup(function () {
	if ($(this).val().length > 0) {
		$(this).data('valid', true);
	} else {
		$(this).data('valid', false);
	}
	toValidate.each(function () {
		if ($(this).data('valid') == true) {
			valid = true;
		} else {
			valid = false;
		}
	});
	if (valid === true) {
		$('button[type=submit]').prop('disabled', false);
	} else {
		$('button[type=submit]').prop('disabled', true);        
	}
});
(function(){
	'use strict';
	var $ = jQuery;
	$.fn.extend({
		filterTable: function(){
			return this.each(function(){
				$(this).on('keyup', function(e){
					$('.filterTable_no_results').remove();
					var $this = $(this),
                        search = $this.val().toLowerCase(),
                        target = $this.attr('data-filters'),
                        $target = $(target),
                        $rows = $target.find('tbody tr');
					if(search == '') {
						$rows.show();
					} else {
						$rows.each(function(){
							var $this = $(this);
							$this.text().toLowerCase().indexOf(search) === -1 ? $this.hide() : $this.show();
						})
						if($target.find('tbody tr:visible').size() === 0) {
							var col_count = $target.find('tr').first().find('td').size();
							var no_results = $('<tr class="filterTable_no_results"><td colspan="'+col_count+'">No results found</td></tr>')
							$target.find('tbody').append(no_results);
						}
					}
				});
			});
		}
	});
	$('[data-action="filter"]').filterTable();
})(jQuery);
$(function(){
	$('[data-action="filter"]').filterTable();
	$('.container').on('click', '.panel-heading span.filter', function(e){
		var $this = $(this),
		$panel = $this.parents('.panel');
		$panel.find('.panel-body').slideToggle("fast");
		if($this.css('display') != 'none') {
			$panel.find('.panel-body input').focus();
		}
	});
	$('[data-toggle="tooltip"]').tooltip();
})
</script>
</body>
</html>
<?php mysqli_close($link); ?>
