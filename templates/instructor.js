const socket = io();

const createQuestionForm = document.getElementById('create-question-form');
const startQuestionButton = document.getElementById('start-question');
const stopQuestionButton = document.getElementById('stop-question');

let currentQuestionId = null;

createQuestionForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const courseName = document.getElementById('course_name').value;
    const questionText = document.getElementById('question_text').value;
    const options = document.getElementById('options').value.split(',').map(option => option.trim());
    const correctAnswer = document.getElementById('correct_answer').value;

    socket.emit('question_event', {
        action: 'create_question',
        course_name: courseName,
        question_text: questionText,
        options: options,
        correct_answer: correctAnswer
    });
});

startQuestionButton.addEventListener('click', () => {
    if (currentQuestionId) {
        socket.emit('question_event', {
            action: 'start_question',
            question_id: currentQuestionId
        });
    }
});

stopQuestionButton.addEventListener('click', () => {
    if (currentQuestionId) {
        socket.emit('question_event', {
            action: 'stop_question',
            question_id: currentQuestionId
        });
    }
});

socket.on('question_created', (data) => {
    currentQuestionId = data.question_id;
    console.log('Question created:', data.question_id);
});

