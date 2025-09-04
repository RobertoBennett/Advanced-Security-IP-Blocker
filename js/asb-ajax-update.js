jQuery(document).ready(function($) {
    // Функция для обновления нумерации строк в textarea
    function updateLineNumbers(textarea, lineNumbers) {
        var lines = textarea.value.split('\n').length;
        var numbersText = '';
        
        for (var i = 1; i <= lines; i++) {
            numbersText += i + '\n';
        }
        
        lineNumbers.textContent = numbersText;
        
        // Синхронизируем прокрутку
        lineNumbers.scrollTop = textarea.scrollTop;
    }
    
    // Инициализация нумерации строк
    $('.ip-blocker-textarea-wrapper').each(function() {
        var wrapper = $(this);
        var textarea = wrapper.find('textarea')[0];
        var lineNumbers = wrapper.find('.ip-blocker-line-numbers')[0];
        
        if (textarea && lineNumbers) {
            // Инициализация при загрузке
            updateLineNumbers(textarea, lineNumbers);
            
            // Обновление при изменении текста
            textarea.addEventListener('input', function() {
                updateLineNumbers(textarea, lineNumbers);
            });
            
            // Синхронизация прокрутки
            textarea.addEventListener('scroll', function() {
                lineNumbers.scrollTop = textarea.scrollTop;
            });
        }
    });
});
